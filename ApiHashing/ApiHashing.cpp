#include <Windows.h>
#include <stdio.h>
#include "ApiHashing.h"
#include "Structs.h"
#include "Win32.h"

#define FASTCALL


#define MAXDLLNAME 64

//-----------------------------------------------------------------------------------------------------------------------------------------------------------------//

typedef HMODULE (WINAPI* fnLoadLibraryA)(LPCSTR lpLibFileName);

HMODULE LoadLibraryH(LPCSTR ModuleName) {
	if (ModuleName == NULL) {
		return NULL;
	}

	fnLoadLibraryA pLoadLibraryA = (fnLoadLibraryA)GetProcAddressH(
						GetModuleHandleH(HASH(kernel32.dll)),
						HASH(LoadLibraryA)
		);

	if (pLoadLibraryA != NULL)
		return pLoadLibraryA(ModuleName);

	return NULL;
}


//-----------------------------------------------------------------------------------------------------------------------------------------------------------------//

FARPROC GetProcAddressH (HMODULE hModule, DWORD64 Hash) {

	if (hModule == NULL || Hash == NULL)
		return NULL;

	PBYTE pFunctionName;
	PIMAGE_DOS_HEADER DosHdr;
	PIMAGE_NT_HEADERS NtHdr;
	PIMAGE_FILE_HEADER FileHdr;
	PIMAGE_OPTIONAL_HEADER OptHdr;
	PIMAGE_EXPORT_DIRECTORY ExportTable;
	FARPROC ReturnAddress = NULL;

	DosHdr = (PIMAGE_DOS_HEADER)hModule;
	if (DosHdr->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

	NtHdr = (PIMAGE_NT_HEADERS)((ULONG_PTR)DosHdr + DosHdr->e_lfanew);
	if (NtHdr->Signature != IMAGE_NT_SIGNATURE)
		return NULL;


	FileHdr = (PIMAGE_FILE_HEADER)((ULONG_PTR)hModule + DosHdr->e_lfanew + sizeof(DWORD));
	OptHdr = (PIMAGE_OPTIONAL_HEADER)((ULONG_PTR)FileHdr + sizeof(IMAGE_FILE_HEADER));
	ExportTable = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)hModule + OptHdr->DataDirectory[0].VirtualAddress);

	PDWORD FunctionNameAddressArray = (PDWORD)((ULONG_PTR)hModule + ExportTable->AddressOfNames);
	PDWORD FunctionAddressArray = (PDWORD)((ULONG_PTR)hModule + ExportTable->AddressOfFunctions);
	PWORD FunctionOrdinalAddressArray = (PWORD)((ULONG_PTR)hModule + ExportTable->AddressOfNameOrdinals);


	for (DWORD i = 0; i < ExportTable->NumberOfNames; i++){
		pFunctionName = (PBYTE)(FunctionNameAddressArray[i] + (ULONG_PTR)hModule);
		if (Hash == HASHA(pFunctionName)) {
			ReturnAddress = (FARPROC)((ULONG_PTR)hModule + FunctionAddressArray[FunctionOrdinalAddressArray[i]]);
			// the following part is from https://github.com/Cracked5pider/KaynLdr/blob/main/KaynLdr/src/Win32.c#L48 thanks for @C5pider 
			if ((ULONG_PTR)ReturnAddress >= (ULONG_PTR)ExportTable && 
				(ULONG_PTR)ReturnAddress < (ULONG_PTR)(ExportTable + (ULONG_PTR)hModule + NtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size)) {
				
				CHAR Library  [MAX_PATH]	= { 0 };
				CHAR Function [MAX_PATH]	= { 0 };
				UINT32 Index = CopyDotStr((PCHAR)ReturnAddress);
				RfCopyMemory((PVOID)Library,  (PVOID)ReturnAddress, Index);
				RfCopyMemory((PVOID)Function, (PVOID)((ULONG_PTR)ReturnAddress + Index + 1), StringLengthA((LPCSTR)((ULONG_PTR)ReturnAddress + Index + 1)));
				if ((hModule = LoadLibraryH(Library)) != NULL) {
					ReturnAddress = GetProcAddressH(hModule, HASHA(Function));
				}
			}
			return ReturnAddress;
		}
	}

	return NULL;
}


//-----------------------------------------------------------------------------------------------------------------------------------------------------------------//

HMODULE GetModuleHandleH (DWORD64 ModuleHash) {
	if (ModuleHash == NULL)
		return NULL;

	PPEB pPeb = (PPEB)__readgsqword(0x60);
	PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);
	PLDR_DATA_TABLE_ENTRY pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);
	while (pDte) {
		if (pDte->FullDllName.Buffer != NULL) {
			if (pDte->FullDllName.Length < MAXDLLNAME - 1) {
				CHAR DllName[MAXDLLNAME] = {0};
				DWORD i = 0;
				while (pDte->FullDllName.Buffer[i] && i < sizeof(DllName) - 1){
					DllName[i] = LowerChar((char)pDte->FullDllName.Buffer[i]);
					i++;
				}
				DllName[i] = '\0';
				if (HASHA(DllName) == ModuleHash) {
					return (HMODULE)(pDte->InInitializationOrderLinks.Flink);
				}
			}
		}
		else {
			break;
		}
		
		pDte = (PLDR_DATA_TABLE_ENTRY)DEREF_64(pDte);
	}
	return NULL;
}

//-----------------------------------------------------------------------------------------------------------------------------------------------------------------//


#ifdef FASTCALL


#include <iostream>
#include <string>
#include <map>

// in case you want a better one (but limited), make a array of struct (2 elements) and replace it with the map 

std::map <HMODULE, DWORD64> FastCallLib ;

BOOL IsFound(DWORD64 ModuleHash, HMODULE* hModule) {
	for (auto& it : FastCallLib) {
		if (it.second == ModuleHash) {
			*hModule = it.first;
			return TRUE;
		}
	}
	return FALSE;
}


FARPROC FastGetProcAddress(DWORD64 ModuleHash, DWORD64 ApiHash) {
	
	HMODULE hModule = NULL;
	
	if (!IsFound(ModuleHash, &hModule)) {
		if ((hModule = GetModuleHandleH(ModuleHash)) == NULL)
			return NULL;
		FastCallLib.insert(std::pair<HMODULE, DWORD64>(hModule, ModuleHash));
	}

	if (hModule == NULL)
		return NULL;

	return GetProcAddressH(hModule, ApiHash);
}


#endif // FASTCALL






















