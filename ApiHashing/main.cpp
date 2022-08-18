#include <Windows.h>
#include <stdio.h>
#include "ApiHashing.h"

// using VirtualAlloc && VirtualProtect && SystemFunction032 Addresses

//#define FASTCALL


VOID PrintAddresses(PVOID pVirtualAlloc, PVOID pVirtualProtect, PVOID pSystemFunction032) {
	printf("[i] pVirtualAlloc : 0x%p \n", pVirtualAlloc);
	printf("[i] pVirtualProtect : 0x%p \n", pVirtualProtect);
	printf("[i] pSystemFunction032 : 0x%p \n", pSystemFunction032);
}


int main() {

	/*
	printf("[i] SEED; 0x%0.2X \n", SEED);

	printf("[N] %s is : 0x%0.8X \n", "VirtualAlloc", HASHA((PCHAR)"VirtualAlloc"));
	printf("[N] %s is : 0x%0.8X \n", "VirtualProtect", HASHA((PCHAR)"VirtualProtect"));
	printf("[N] %s is : 0x%0.8X \n", "SystemFunction032", HASHA((PCHAR)"SystemFunction032"));

	printf("[T] %s is : 0x%0.8X \n", "VirtualAlloc", HASH(VirtualAlloc));
	printf("[T] %s is : 0x%0.8X \n", "VirtualProtect", HASH(VirtualProtect));
	printf("[T] %s is : 0x%0.8X \n", "SystemFunction032", HASH(SystemFunction032));
	*/




	PVOID pVirtualAlloc = NULL, pVirtualProtect = NULL, pSystemFunction032 = NULL;
	HMODULE hModule = NULL;
	// just to get it in the memory to test forwarded api's  :
	LoadLibraryA("Advapi32.dll");




#ifndef FASTCALL

	printf("\n\t\t-------------------- PRINTING 1 --------------------\n");

	if (!(hModule = GetModuleHandleH(HASH(kernel32.dll)))) {
		return NULL;
	}

	pVirtualAlloc = (PVOID)GetProcAddressH(hModule, HASH(VirtualAlloc));
	pVirtualProtect = (PVOID)GetProcAddressH(hModule, HASH(VirtualProtect));

	
	
	if (!(hModule = GetModuleHandleH(HASH(advapi32.dll)))) {
		return NULL;
	}
	pSystemFunction032 = (PVOID)GetProcAddressH(hModule, HASH(SystemFunction032));


	PrintAddresses(pVirtualAlloc, pVirtualProtect, pSystemFunction032);

#else

	printf("\n\t\t-------------------- PRINTING 1 --------------------\n");

	pVirtualAlloc = FastGetProcAddress(HASH(kernel32.dll), HASH(VirtualAlloc));
	pVirtualProtect = FastGetProcAddress(HASH(kernel32.dll), HASH(VirtualProtect));
	pSystemFunction032 = FastGetProcAddress(HASH(advapi32.dll), HASH(SystemFunction032));


	PrintAddresses(pVirtualAlloc, pVirtualProtect, pSystemFunction032);


#endif // !FASTCALL


	printf("\n\t\t-------------------- PRINTING 2 --------------------\n");

	if (!(hModule = GetModuleHandleA("Kernel32.dll"))) {
		return NULL;
	}
	pVirtualAlloc		= GetProcAddress(hModule, "VirtualAlloc");
	pVirtualProtect		= GetProcAddress(hModule, "VirtualProtect");



	if (!(hModule = GetModuleHandleA("Advapi32.dll"))) {
		return NULL;
	}
	pSystemFunction032 = GetProcAddress(hModule, "SystemFunction032");




	PrintAddresses(pVirtualAlloc, pVirtualProtect, pSystemFunction032);




	printf("\n\n[i] Press <Enter> to Quit ... ");
	getchar();
	return 0;

}



