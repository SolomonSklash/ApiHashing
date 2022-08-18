#pragma once

#ifndef _WIN32_H
#define _WIN32_H

#include <Windows.h>

SIZE_T StringLengthA(LPCSTR String);

SIZE_T StringLengthW(LPCWSTR String);

DWORD64 HashStringRotr32A(PCHAR String);

DWORD64 HashStringRotr32W(PWCHAR String);

unsigned char LowerChar(unsigned char ch);

UINT32 CopyDotStr(PCHAR String);

PVOID RfCopyMemory(PVOID Destination, CONST PVOID Source, SIZE_T Length);

// from https://github.com/rad9800/WTSRM/blob/master/WTSRM/entry.cpp#L152 thanks to @rad98
constexpr int RandomSeed(void)
{
	return '0' * -40271 + // offset accounting for digits' ANSI offsets
		__TIME__[7] * 1 +
		__TIME__[6] * 10 +
		__TIME__[4] * 60 +
		__TIME__[3] * 600 +
		__TIME__[1] * 3600 +
		__TIME__[0] * 36000;
};

constexpr auto SEED = RandomSeed() % 0xFF;

#endif // !_WIN32_H
