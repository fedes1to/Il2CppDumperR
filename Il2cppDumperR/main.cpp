// main.cpp — cross-platform entry point and orchestration for Il2CppDumperR.
//
// Builds as:
//   * Il2cppDumperR.dll  (Windows / Wine, inject into the game process)
//   * libIl2cppDumperR.so (native Linux, LD_PRELOAD or dlopen-inject)

#include <cstdlib>
#include <fstream>
#include <string>

#include "platform.hpp"
#include "log.hpp"
#include "json.hpp"
#include "sigz.hpp"

#include "il2cpp/il2cpp-api-types.h"
#include "il2cpp/il2cpp-tabledefs.h"

// dummy definitions so the compiler doesn't kill itself
#define DO_API(r, n, p) r(*n) p
#include "il2cpp/il2cpp-api-functions.h"
#undef DO_API

#include "state.hpp"
#include "il2cpp/il2cpp-wrapper.h"
#include "resolve.hpp"
#include "classdump.h"
#include "strings.hpp"
#include "hook.hpp"

// ---------------------------------------------------------------------------
// Unity / metadata version detection
// ---------------------------------------------------------------------------

static const char* metadata_version_note(int v) {
    if (v == 0)  return "unknown (global-metadata.dat not found)";
    if (v <= 24) return "Unity 5.6 - 2019.2 era";
    if (v == 27) return "Unity 2019.3 - 2021.1 era";
    if (v == 29) return "Unity 2021.2 - 2022.1 era";
    if (v >= 31) return "Unity 2022.2+ era";
    return "recent Unity";
}

// ---------------------------------------------------------------------------
// Worker
// ---------------------------------------------------------------------------

static void dump_worker(void* module_handle) {
    plat::open_console();

    dlog::info("Il2CppDumperR injected (%s build)", plat::platform_name);
    dlog::info("waiting for GameAssembly...");

    il2cppHandle = plat::wait_for_game_assembly();
    il2cppBase = plat::module_base(plat::game_assembly_module_name());
    dlog::good("found %s @ %p", plat::game_assembly_module_name(), il2cppBase);

    // output directory: IL2CPP_DUMP_DIR env override, else a config file next
    // to this module (written by the loader), else the game folder.
    std::string dump_dir;
    auto read_dump_dir = [&]() -> std::string {
        if (const char* env = std::getenv("IL2CPP_DUMP_DIR"); env && *env)
            return env;
#ifdef _WIN32
        wchar_t mod[MAX_PATH];
        // the config lives next to THIS dll, not next to the game exe.
        // GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS always finds our own module
        // regardless of how the loader named it.
        HMODULE self = nullptr;
        if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                               GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                               reinterpret_cast<LPCWSTR>(&dump_worker), &self) &&
            GetModuleFileNameW(self, mod, MAX_PATH)) {
            std::string dir = plat::wide_to_utf8(mod);
            dir = dir.substr(0, dir.find_last_of("\\/"));
            std::ifstream f(dir + "\\il2cpp_dump_dir.txt");
            std::string line;
            if (f && std::getline(f, line) && !line.empty()) {
                line.erase(line.find_last_not_of(" \t\r\n") + 1);
                return line;
            }
        }
#else
        Dl_info info;
        if (dladdr((void*)&dump_worker, &info) && info.dli_fname) {
            std::string dir = info.dli_fname;
            dir = dir.substr(0, dir.find_last_of('/'));
            std::ifstream f(dir + "/il2cpp_dump_dir.txt");
            std::string line;
            if (f && std::getline(f, line) && !line.empty()) {
                line.erase(line.find_last_not_of(" \t\r\n") + 1);
                return line;
            }
        }
#endif
        return "";
    };
    dump_dir = read_dump_dir();
    if (dump_dir.empty())
        dump_dir = plat::executable_dir();
    else
        dlog::info("dump output dir: %s", dump_dir.c_str());

    // Resolve the il2cpp API (exports first, signature fallback for
    // obfuscated/stripped GameAssembly builds).
    il2cpp_fallback_resolver = &resolve::resolve_by_signature;
    for (int attempt = 0; attempt < 50; ++attempt) {
        init_il2cpp_api(il2cppHandle);
        if (il2cpp_domain_get && il2cpp_class_for_each)
            break;
        plat::sleep_ms(100);
    }

    if (!il2cpp_domain_get || !il2cpp_class_for_each) {
        dlog::error("failed to resolve core il2cpp API (il2cpp_domain_get / il2cpp_class_for_each)");
        dlog::error("this GameAssembly may be protected — check resolve.hpp signatures");
    } else {
        if (!il2cpp_unresolved_apis.empty())
            dlog::warn("%zu optional il2cpp exports unresolved (version differences?)", il2cpp_unresolved_apis.size());

        // metadata version + string literal definitions (multi-version support)
        il2cpp_metadata = meta::load(plat::executable_dir());
        il2cpp_metadata_version = il2cpp_metadata.version;
        dlog::info("metadata version: %d (%s)", il2cpp_metadata_version, metadata_version_note(il2cpp_metadata_version));
        if (il2cpp_metadata.valid)
            dlog::info("string literal definitions: %zu", il2cpp_metadata.literals.size());

        // wait until the il2cpp VM is up
        if (il2cpp_is_vm_thread)
            while (!il2cpp_is_vm_thread(nullptr))
                plat::sleep_ms(100);

        il2cpp_domain = il2cpp_domain_get();
        if (il2cpp_thread_attach)
            il2cpp_thread_attach(il2cpp_domain); // attach to game

        // install the literal-use hook (opt-in). The static xref scan works
        // without it; the hook captures live (index, return-address) uses while
        // the game runs. Enabled by IL2CPP_STRING_HOOK=1 env OR a config file
        // "il2cpp_string_hook.txt" (contents "1") next to this module — the
        // loader writes the config file, which survives wine env propagation.
        bool want_hook = false;
        {
            const char* hook_env = std::getenv("IL2CPP_STRING_HOOK");
            want_hook = hook_env && *hook_env == '1';
#ifdef _WIN32
            HMODULE self = nullptr;
            wchar_t mod[MAX_PATH];
            if (!want_hook && GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                                 GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                                 reinterpret_cast<LPCWSTR>(&dump_worker), &self) &&
                GetModuleFileNameW(self, mod, MAX_PATH)) {
                std::string dir = plat::wide_to_utf8(mod);
                dir = dir.substr(0, dir.find_last_of("\\/"));
                std::ifstream f(dir + "\\il2cpp_string_hook.txt");
                std::string line;
                if (f && std::getline(f, line))
                    want_hook = line.find('1') != std::string::npos;
            }
#else
            if (!want_hook) {
                Dl_info info;
                if (dladdr((void*)&dump_worker, &info) && info.dli_fname) {
                    std::string dir = info.dli_fname;
                    dir = dir.substr(0, dir.find_last_of('/'));
                    std::ifstream f(dir + "/il2cpp_string_hook.txt");
                    std::string line;
                    if (f && std::getline(f, line))
                        want_hook = line.find('1') != std::string::npos;
                }
            }
#endif
        }
        if (want_hook) {
            dlog::info("string-use hook ENABLED (live literal capture)");
            hook::install();
        }

        // dump the game (funky method im aware)
        dlog::info("dumping classes...");
        il2cpp_class_for_each(dump_class, nullptr);
        dlog::good("finished dumping %d classes", dumped_class_count);

        // dump string literals from memory
        strdump::dump_strings(il2cpp_metadata);

        // string <-> method xrefs (requires the classes dump + table)
        strdump::build_string_xrefs(il2cpp_metadata, strdump::g_found_table);

        // real-time literal uses captured by the hook (index + return addr)
        hook::uninstall();
        std::vector<hook::literal_use> uses;
        hook::take_uses(uses);
        dlog::info("captured %zu real-time literal uses", uses.size());
        if (!uses.empty())
            strdump::annotate_from_live_uses(uses);

        // write the class dump AFTER xrefs so method annotations land on disk
        const std::string dir = dump_dir;
        try {
            std::ofstream out(dir + "/il2cpp_classes.json", std::ios::trunc);
            out << il2cpp_classes.dump(4);
            dlog::good("wrote %s/il2cpp_classes.json", dir.c_str());
        } catch (const std::exception& e) {
            dlog::error("failed writing class dump: %s", e.what());
        }

        if (!il2cpp_strings.empty()) {
            try {
                std::ofstream out(dir + "/il2cpp_strings.json", std::ios::trunc);
                out << il2cpp_strings.dump(4);
                dlog::good("wrote %s/il2cpp_strings.json", dir.c_str());
            } catch (const std::exception& e) {
                dlog::error("failed writing strings dump: %s", e.what());
            }
        }

        if (il2cpp_thread_detach && il2cpp_thread_current)
            il2cpp_thread_detach(il2cpp_thread_current());
    }

    dlog::info("done. you can close this window.");

#ifdef _WIN32
    // unload ourselves (thread was created with the module handle as arg)
    if (module_handle)
        FreeLibraryAndExitThread(static_cast<HMODULE>(module_handle), 0);
#else
    (void)module_handle;
#endif
}

// ---------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------

#ifdef _WIN32
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        plat::start_worker_thread(dump_worker, hModule);
    }
    return TRUE;
}
#else
__attribute__((constructor)) static void il2cppdumper_onload() {
    plat::start_worker_thread(dump_worker, nullptr);
}
#endif
