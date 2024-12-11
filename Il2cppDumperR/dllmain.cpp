// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "json.hpp"
#include "il2cpp/il2cpp-api-types.h"
#include "il2cpp/il2cpp-tabledefs.h"

// dummy definitions so the compiler doesn't kill itself
#define DO_API(r, n, p) r(*n) p
#include "il2cpp/il2cpp-api-functions.h"
#undef DO_API

HMODULE il2cppHandle;
Il2CppDomain *il2cpp_domain;
const Il2CppImage *il2cpp_corlib;
nlohmann::json il2cpp_dump;

#include "il2cpp/il2cpp-wrapper.h"
#include "classdump.h"

static DWORD WINAPI MainThread(LPVOID lpReserved)
{
    // show console
    AllocConsole();
    FILE *fp;
    freopen_s(&fp, "CONOUT$", "w", stdout);
    freopen_s(&fp, "CONOUT$", "w", stderr);

    // Get handle to GameAssembly.dll
    while (!(il2cppHandle = GetModuleHandle(L"GameAssembly.dll")))
        Sleep(100);
    if (il2cppHandle)
        while (!il2cpp_domain_get_assemblies)
        {
            init_il2cpp_api(il2cppHandle); // Initialize il2cpp api
            Sleep(100);
        }
    else
        std::cerr << "Failed to init il2cpp api" << std::endl;

    while (!il2cpp_is_vm_thread(nullptr))
        Sleep(100);

    il2cpp_domain = il2cpp_domain_get();
    il2cpp_thread_attach(il2cpp_domain); // attach to game

    // dump the game (funky method im aware)
    il2cpp_class_for_each(dump_class, nullptr);

    std::cout << "Finished Dumping All Classes!" << std::endl;

    // delete the file if it already exists
    DeleteFile(L"il2cpp_dump.json");

    // write to file
    WriteFile(
        CreateFile(L"il2cpp_dump.json", GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr),
        il2cpp_dump.dump(4).c_str(), il2cpp_dump.dump(4).length(), nullptr, nullptr);

    std::cout << "Created JSON file at the game's folder." << std::endl;

    il2cpp_thread_detach(il2cpp_thread_current());

    // close console
    fclose(fp);
    FreeConsole();

    FreeLibraryAndExitThread(static_cast<HMODULE>(lpReserved), 0);

    return TRUE;
}

BOOL APIENTRY DllMain(HMODULE hModule,
                      DWORD ul_reason_for_call,
                      LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        CreateThread(nullptr, 0, MainThread, hModule, 0, nullptr);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}