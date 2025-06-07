#pragma once
#include "sekurlsa.h"


VOID LocateUnprotectLsassMemoryKeys();
VOID GetCredentialsFromMSV();
VOID GetCredentialsFromWdigest();
BOOL EnableSeDebugPrivilege();
// void printStruct(const KIWI_MSV1_0_LIST_63& s);