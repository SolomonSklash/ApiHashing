// the following code is from : https://github.com/vxunderground/VX-API
#include <Windows.h>
#include "Win32.h"


//-----------------------------------------------------------------------------------------------------------------------------------------------------------------//

SIZE_T StringLengthA(LPCSTR String)
{
	LPCSTR String2;

	for (String2 = String; *String2; ++String2);

	return (String2 - String);
}

SIZE_T StringLengthW(LPCWSTR String)
{
	LPCWSTR String2;

	for (String2 = String; *String2; ++String2);

	return (String2 - String);
}

//-----------------------------------------------------------------------------------------------------------------------------------------------------------------//

UINT32 HashStringRotr32SubA(UINT32 Value, UINT Count)
{
	DWORD Mask = (CHAR_BIT * sizeof(Value) - 1);
	Count &= Mask;
#pragma warning( push )
#pragma warning( disable : 4146)
	return (Value >> Count) | (Value << ((-Count) & Mask));
#pragma warning( pop ) 
}

DWORD64 HashStringRotr32A(PCHAR String)
{
	DWORD64 Value = 0;

	for (INT Index = 0; Index < StringLengthA(String); Index++)
		Value = String[Index] + HashStringRotr32SubA(Value, SEED);

	return Value;
}
//-----------------------------------------------------------------------------------------------------------------------------------------------------------------//

UINT32 HashStringRotr32SubW(UINT32 Value, UINT Count)
{
	DWORD Mask = (CHAR_BIT * sizeof(Value) - 1);
	Count &= Mask;
#pragma warning( push )
#pragma warning( disable : 4146)
	return (Value >> Count) | (Value << ((-Count) & Mask));
#pragma warning( pop ) 
}


DWORD64 HashStringRotr32W(PWCHAR String)
{
	DWORD64 Value = 0;

	for (INT Index = 0; Index < StringLengthW(String); Index++)
		Value = String[Index] + HashStringRotr32SubW(Value, SEED);

	return Value;
}
//-----------------------------------------------------------------------------------------------------------------------------------------------------------------//

unsigned char LowerChar(unsigned char ch) {
	if (ch >= 'A' && ch <= 'Z')
		ch = 'a' + (ch - 'A');
	return ch;
}

//-----------------------------------------------------------------------------------------------------------------------------------------------------------------//

UINT32 CopyDotStr(PCHAR String)
{
	for (UINT32 i = 0; i < StringLengthA(String); i++)
	{
		if (String[i] == '.')
			return i;
	}
}

//-----------------------------------------------------------------------------------------------------------------------------------------------------------------//

PVOID RfCopyMemory(PVOID Destination, CONST PVOID Source, SIZE_T Length)
{
	PBYTE D = (PBYTE)Destination;
	PBYTE S = (PBYTE)Source;

	while (Length--)
		*D++ = *S++;

	return Destination;
}