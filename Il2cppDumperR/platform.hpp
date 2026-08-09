#pragma once
// platform.hpp — OS abstraction so the dumper builds as:
//   * a Windows DLL (MSVC or MinGW, also runs under Wine)
//   * a native Linux .so  (dlopen/dlsym based)
//
// Everything the rest of the code needs from the OS goes through here.

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <chrono>
#include <vector>
#include <algorithm>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <dlfcn.h>
#include <link.h>
#include <unistd.h>
#include <limits.h>
#include <dirent.h>
#include <fcntl.h>
#endif

#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

namespace plat {

#ifdef _WIN32
    using module_handle = HMODULE;
    static constexpr const char* game_assembly_names[] = { "GameAssembly.dll" };
    static constexpr const char* platform_name = "windows";
#else
    using module_handle = void*;
    static constexpr const char* game_assembly_names[] = { "GameAssembly.so", "libGameAssembly.so" };
    static constexpr const char* platform_name = "linux";
#endif

    inline void sleep_ms(int ms) {
        std::this_thread::sleep_for(std::chrono::milliseconds(ms));
    }

    // Returns a handle to an already-loaded module (never loads it).
    inline module_handle get_module(const char* name) {
#ifdef _WIN32
#ifdef _UNICODE
        wchar_t wname[MAX_PATH];
        std::mbstowcs(wname, name, MAX_PATH);
        return GetModuleHandleW(wname);
#else
        return GetModuleHandleA(name);
#endif
#else
        // dlopen(name, RTLD_NOLOAD) name matching is unreliable (depends on the
        // exact path the loader used), so find the object via the program
        // headers first and then grab its handle by the exact path.
        struct ctx { const char* name; char path[PATH_MAX]; };
        ctx c{ name, {} };
        dl_iterate_phdr([](struct dl_phdr_info* info, size_t, void* data) -> int {
            auto* c = static_cast<ctx*>(data);
            if (!info->dlpi_name || !*info->dlpi_name)
                return 0;
            const char* base = std::strrchr(info->dlpi_name, '/');
            base = base ? base + 1 : info->dlpi_name;
            if (std::strcmp(base, c->name) == 0) {
                std::strncpy(c->path, info->dlpi_name, PATH_MAX - 1);
                return 1;
            }
            return 0;
        }, &c);
        if (!*c.path)
            return nullptr;
        return dlopen(c.path, RTLD_LAZY | RTLD_NOLOAD);
#endif
    }

    // Spins until GameAssembly is mapped into the process.
    inline module_handle wait_for_game_assembly() {
        for (;;) {
            for (const char* name : game_assembly_names) {
                if (module_handle h = get_module(name))
                    return h;
            }
            sleep_ms(100);
        }
    }

    inline const char* game_assembly_module_name() {
        for (const char* name : game_assembly_names) {
            if (get_module(name))
                return name;
        }
        return game_assembly_names[0];
    }

    inline void* get_proc(module_handle h, const char* name) {
#ifdef _WIN32
        return reinterpret_cast<void*>(GetProcAddress(h, name));
#else
        return dlsym(h, name);
#endif
    }

    // Base address of a loaded module (nullptr if not loaded).
    inline void* module_base(const char* name) {
#ifdef _WIN32
        return reinterpret_cast<void*>(get_module(name));
#else
        module_handle h = get_module(name);
        if (!h)
            return nullptr;
        struct link_map* lm = nullptr;
        if (dlinfo(h, RTLD_DI_LINKMAP, &lm) != 0 || !lm)
            return nullptr;
        return reinterpret_cast<void*>(lm->l_addr);
#endif
    }

    // Directory of the main executable — the "game folder", where the dump is written.
    inline std::string executable_dir() {
#ifdef _WIN32
        char path[MAX_PATH];
        DWORD len = GetModuleFileNameA(nullptr, path, MAX_PATH);
        std::string p(path, len);
        return p.substr(0, p.find_last_of("\\/"));
#else
        char path[PATH_MAX];
        ssize_t len = readlink("/proc/self/exe", path, sizeof(path) - 1);
        if (len <= 0)
            return ".";
        path[len] = '\0';
        std::string p(path);
        return p.substr(0, p.find_last_of('/'));
#endif
    }

#ifdef _WIN32
    // Converts a UTF-16 windows string to UTF-8.
    inline std::string wide_to_utf8(const wchar_t* w) {
        std::string out;
        for (; *w; ++w) {
            uint32_t cp = static_cast<uint32_t>(*w);
            if (cp >= 0xD800 && cp <= 0xDBFF && w[1] >= 0xDC00 && w[1] <= 0xDFFF) {
                cp = 0x10000 + ((cp - 0xD800) << 10) + (static_cast<uint32_t>(w[1]) - 0xDC00);
                ++w;
            }
            if (cp < 0x80) out.push_back(static_cast<char>(cp));
            else if (cp < 0x800) {
                out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
                out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
            } else if (cp < 0x10000) {
                out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
                out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
                out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
            } else {
                out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
                out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
                out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
                out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
            }
        }
        return out;
    }
#endif

    // Opens a console window for logging (no-op on Linux, stdout is already there).
    inline void open_console() {
#ifdef _WIN32
        AllocConsole();
        freopen("CONOUT$", "w", stdout);
        freopen("CONOUT$", "w", stderr);
#endif
    }

    inline void close_console() {
#ifdef _WIN32
        FreeConsole();
#endif
    }

    // Contiguous readable memory regions belonging to a module (PE sections /
    // ELF mappings). Used by pattern scanning over a module's memory.
    struct region { void* first; void* last; bool executable = false; };

    inline std::vector<region> module_regions(const char* name) {
        std::vector<region> out;
#ifdef _WIN32
        auto* base = reinterpret_cast<unsigned char*>(get_module(name));
        if (!base)
            return out;
        auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
        auto* sec = IMAGE_FIRST_SECTION(nt);
        for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
            if (sec->Misc.VirtualSize == 0)
                continue;
            out.push_back({ base + sec->VirtualAddress,
                            base + sec->VirtualAddress + sec->Misc.VirtualSize,
                            (sec->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0 });
        }
#else
        std::string mod = name;
        FILE* f = std::fopen("/proc/self/maps", "r");
        if (!f)
            return out;
        char line[1024];
        while (std::fgets(line, sizeof(line), f)) {
            unsigned long long start = 0, end = 0;
            char perms[8] = {};
            char path[512] = {};
            int fields = std::sscanf(line, "%llx-%llx %7s %*s %*s %*s %511[^\n]", &start, &end, perms, path);
            if (fields < 3 || perms[0] != 'r')
                continue;
            std::string p(path);
            if (p.length() < mod.length() || p.compare(p.length() - mod.length(), mod.length(), mod) != 0)
                continue;
            out.push_back({ reinterpret_cast<void*>(start), reinterpret_cast<void*>(end),
                            perms[2] == 'x' });
        }
        std::fclose(f);
#endif
        return out;
    }

    // All readable regions of the process (for heap validation of pointers).
    inline std::vector<region> readable_regions() {
        std::vector<region> out;
#ifdef _WIN32
        MEMORY_BASIC_INFORMATION mbi{};
        unsigned char* addr = nullptr;
        while (VirtualQuery(addr, &mbi, sizeof(mbi))) {
            if (mbi.State == MEM_COMMIT && (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY)))
                out.push_back({ mbi.BaseAddress, static_cast<unsigned char*>(mbi.BaseAddress) + mbi.RegionSize });
            addr = static_cast<unsigned char*>(mbi.BaseAddress) + mbi.RegionSize;
            if (addr == nullptr)
                break;
        }
#else
        FILE* f = std::fopen("/proc/self/maps", "r");
        if (!f)
            return out;
        char line[1024];
        while (std::fgets(line, sizeof(line), f)) {
            unsigned long long start = 0, end = 0;
            char perms[8] = {};
            if (std::sscanf(line, "%llx-%llx %7s", &start, &end, perms) < 3 || perms[0] != 'r')
                continue;
            out.push_back({ reinterpret_cast<void*>(start), reinterpret_cast<void*>(end) });
        }
        std::fclose(f);
#endif
        std::sort(out.begin(), out.end(), [](const region& a, const region& b) { return a.first < b.first; });
        return out;
    }

    inline bool is_readable(const std::vector<region>& regions, const void* ptr, size_t len) {
        // regions must be sorted; binary search for a region covering [ptr, ptr+len)
        auto it = std::upper_bound(regions.begin(), regions.end(), ptr,
            [](const void* p, const region& r) { return p < r.first; });
        if (it == regions.begin())
            return false;
        --it;
        return ptr >= it->first && static_cast<const unsigned char*>(ptr) + len <= static_cast<const unsigned char*>(it->last);
    }

    // Race-free memory read from our own process. A plain dereference can
    // crash when the il2cpp GC concurrently protects/unmaps heap pages;
    // ReadProcessMemory/self and pread(/proc/self/mem) fail gracefully instead.
    inline bool safe_read(const void* src, void* dst, size_t len) {
#ifdef _WIN32
        SIZE_T n = 0;
        return ReadProcessMemory(GetCurrentProcess(), src, dst, len, &n) && n == len;
#else
        static int mem_fd = open("/proc/self/mem", O_RDONLY);
        if (mem_fd < 0)
            return false;
        ssize_t n = pread(mem_fd, dst, len, reinterpret_cast<off_t>(src));
        return n == static_cast<ssize_t>(len);
#endif
    }

    template <class T>
    inline bool safe_read(const void* src, T& out) {
        return safe_read(src, &out, sizeof(T));
    }

    // Starts the dumper worker without disturbing the loader/constructor context.
    inline void start_worker_thread(void (*fn)(void*), void* arg) {
#ifdef _WIN32
        // CreateThread is safe to call from DllMain (unlike std::thread join/detach
        // which can deadlock under loader lock on some CRTs).
        CreateThread(nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(fn), arg, 0, nullptr);
#else
        (void)arg;
        std::thread([fn, arg] { fn(arg); }).detach();
#endif
    }

}
