// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "json.hpp"
#include "sigz.hpp"
#include "il2cpp/il2cpp-api-types.h"
#include "il2cpp/il2cpp-tabledefs.h"

// dummy definitions so the compiler doesn't kill itself
#define DO_API(r, n, p) r(*n) p
#include "il2cpp/il2cpp-api-functions.h"
#undef DO_API

HMODULE il2cppHandle;
Il2CppDomain *il2cpp_domain;
const Il2CppImage *il2cpp_corlib;
nlohmann::json il2cpp_classes, il2cpp_strings;

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
    DeleteFile(L"il2cpp_class_dump.json");

    // write to file
    WriteFile(
        CreateFile(L"il2cpp_classes.json", GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr),
        il2cpp_classes.dump(4).c_str(), il2cpp_classes.dump(4).length(), nullptr, nullptr);

    std::cout << "Created JSON file at the game's folder." << std::endl;

    /*
        // Get s_StringLiteralTable from GameAssembly.dll using InitializeStringLiteralTable
        auto result = sigz::scan_image_first("GameAssembly.dll", sigz::make_sig<sigz::ida>("48 83 EC 28 48 8B 05 ? ? ? ? 33 D2"));

        if (result.has_value())
        {
            std::cout << "Found InitializeStringLiteralTable at: " << std::hex << result.value() << std::endl;
            uintptr_t initializeStringLiteralTableAddr = (uintptr_t)result.value() + 0x1A;

            // Extract the offset from the instruction
            int32_t offset = *(int32_t*)(initializeStringLiteralTableAddr + 3);

            // Calculate the absolute address
            uintptr_t s_StringLiteralTableAddr = initializeStringLiteralTableAddr + 7 + offset;
            Il2CppString** s_StringLiteralTable = (Il2CppString**)s_StringLiteralTableAddr;

            for (int i = 0; i < 10000; i++) // 10000 is just a random number
            {
                Il2CppString* stringInstance = s_StringLiteralTable[i];
                uintptr_t stringAddr = (uintptr_t)stringInstance;
                if (stringAddr > (uintptr_t)il2cppHandle && stringAddr < 1000000000000000)
                    std::cout << "s_StringLiteralTable[" << i << "]: " << stringAddr << ", value: " << stringInstance->getString() << std::endl;
            }
        }
        else
        {
            std::cerr << "Failed to find InitializeStringLiteralTable" << std::endl;
        }
    */

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
