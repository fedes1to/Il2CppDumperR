// injector.cpp — tiny command-line injector (Windows / Wine).
//
//   injector.exe <process-name.exe | pid> <C:\path\to\dll>
//
// Used by Il2CppLoader on Windows directly, and on Linux through Wine
// (the loader converts the dll path with winepath first).
//
// Method: classic VirtualAllocEx + WriteProcessMemory + CreateRemoteThread(LoadLibraryW).

#include <windows.h>
#include <tlhelp32.h>
#include <cstdio>
#include <cwchar>
#include <string>

static DWORD find_process(const wchar_t* nameOrPid) {
    // numeric? treat as pid
    if (nameOrPid[0] >= L'0' && nameOrPid[0] <= L'9') {
        return (DWORD)_wtoi(nameOrPid);
    }
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return 0;
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    DWORD pid = 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, nameOrPid) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

int wmain(int argc, wchar_t** argv) {
    if (argc < 3) {
        std::fwprintf(stderr, L"usage: injector.exe <process-name.exe | pid> <dll-path>\n");
        return 2;
    }

    DWORD pid = find_process(argv[1]);
    if (!pid) {
        std::fwprintf(stderr, L"[-] process not found: %ls\n", argv[1]);
        return 1;
    }

    // absolute path required by LoadLibrary in the remote process
    wchar_t fullPath[MAX_PATH];
    if (!GetFullPathNameW(argv[2], MAX_PATH, fullPath, nullptr)) {
        std::fwprintf(stderr, L"[-] bad dll path\n");
        return 1;
    }

    HANDLE proc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                              PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
                              FALSE, pid);
    if (!proc) {
        std::fwprintf(stderr, L"[-] OpenProcess(%lu) failed: %lu\n", pid, GetLastError());
        return 1;
    }

    size_t bytes = (std::wcslen(fullPath) + 1) * sizeof(wchar_t);
    LPVOID remote = VirtualAllocEx(proc, nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote || !WriteProcessMemory(proc, remote, fullPath, bytes, nullptr)) {
        std::fwprintf(stderr, L"[-] remote write failed: %lu\n", GetLastError());
        CloseHandle(proc);
        return 1;
    }

    auto loadLibraryW = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
    HANDLE thread = CreateRemoteThread(proc, nullptr, 0, loadLibraryW, remote, 0, nullptr);
    if (!thread) {
        std::fwprintf(stderr, L"[-] CreateRemoteThread failed: %lu\n", GetLastError());
        VirtualFreeEx(proc, remote, 0, MEM_RELEASE);
        CloseHandle(proc);
        return 1;
    }

    WaitForSingleObject(thread, 15000);
    DWORD exitCode = 0;
    GetExitCodeThread(thread, &exitCode); // LoadLibrary return value (module handle)

    CloseHandle(thread);
    VirtualFreeEx(proc, remote, 0, MEM_RELEASE);
    CloseHandle(proc);

    if (!exitCode) {
        std::fwprintf(stderr, L"[-] LoadLibraryW returned NULL in target\n");
        return 1;
    }

    std::wprintf(L"[+] injected into pid %lu (module 0x%lx)\n", pid, exitCode);
    return 0;
}
