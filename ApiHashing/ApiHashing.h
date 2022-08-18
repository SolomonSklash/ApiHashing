#pragma once


#ifndef _API_HASHING_H_
#define _API_HASHING_H_

#include <Windows.h>
#include "Win32.h"


FARPROC GetProcAddressH(HMODULE hModule, DWORD64 Hash);
HMODULE GetModuleHandleH(DWORD64 ModuleHash);

FARPROC FastGetProcAddress(DWORD64 ModuleHash, DWORD64 ApiHash);

#define HASHA(API) (HashStringRotr32A((PCHAR) API))
#define HASHW(API) (HashStringRotr32W((PWCHAR) API))

#define HASH(API) (HashStringRotr32A((PCHAR) #API))

#define DEREF_64( name )*(DWORD64 *)(name)

#endif // !_API_HASHING_H_
