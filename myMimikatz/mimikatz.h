#pragma once
#include "sekurlsa.h"
#define NTLMHASH_OFFSET 0x4a
#define NTLMHASH_SIZE 16

VOID LocateUnprotectLsassMemoryKeys();
VOID GetCredentialsFromMSV();
VOID GetCredentialsFromWdigest();
BOOL EnableSeDebugPrivilege();
// void printStruct(const KIWI_MSV1_0_LIST_63& s);