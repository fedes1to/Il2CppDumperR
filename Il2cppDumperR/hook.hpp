#pragma once
// hook.hpp — inline hook on the il2cpp string-literal dispatcher.
//
// Modern il2cpp routes EVERY string literal access through a single
// MetadataCache function that takes the encoded token in ecx/edi:
//
//     (type << 29) | (index << 1) | 1      type 5 = string literal
//
// By hooking that function we observe, in real time, every literal the game
// actually uses together with the return address — the definitive per-string
// xref source, even for stripped/dedicated-server builds where static
// scanning finds almost nothing.
//
// The hook is a 5-byte jmp detour (the dispatcher prologue is
// `push rdi; sub rsp,20h`). The target is resolved by signature with a
// fallback to a known RVA.
//
// Trampoline: [stolen prologue bytes] + jmp [target+stolen].
// Jumpback:   mov rax, imm64; jmp rax   (returns to target+stolen).
//
// The hook body is a tiny naked stub that saves volatiles, calls a C++ logger
// with the token, restores, then jumps to the trampoline.

#include <cstdint>
#include <cstring>
#include <mutex>
#include <vector>
#include <atomic>
#include <cstdio>
#include <cstdarg>

#include "platform.hpp"
#include "log.hpp"
#include "sigz.hpp"

#ifdef _WIN32
#include <windows.h>
#include <intrin.h>
#else
#include <sys/mman.h>
#endif

namespace hook {

    struct literal_use {
        uint32_t index;
        uintptr_t ret_addr;
    };

    inline std::vector<literal_use> g_literal_uses;
    inline std::mutex g_hook_mutex;
    inline bool g_hook_active = false;
    inline uintptr_t g_target = 0;
    inline uintptr_t g_trampoline = 0;
    inline unsigned char g_original[16] = {};
    inline int g_stolen = 5;
    inline void* g_jumpback = nullptr;


    // C++ logger called from the naked stub (kept in the header so both
    // Windows/Linux builds share it). ret_addr is captured by the stub.
    extern "C" inline void literal_hook_c(uint32_t token, uintptr_t ret_addr) {
        uint32_t type = token >> 29;
        uint32_t idx = (token >> 1) & 0xFFFFFFF;
        if (type == 5 && idx < 0x400000) {
            std::lock_guard<std::mutex> lk(g_hook_mutex);
            if (g_literal_uses.size() < 2000000)
                g_literal_uses.push_back({ idx, ret_addr });
        }
    }

    // Hook body: a plain C++ function (no naked asm). Called with the token in
    // the ABI arg reg. Logs the use, then transfers to the trampoline, which
    // replays the stolen prologue and jumps to target+5.
    extern "C" uintptr_t literal_hook_dispatch(uintptr_t token) {
        uint32_t type = static_cast<uint32_t>(token >> 29);
        uint32_t idx = static_cast<uint32_t>((token >> 1) & 0xFFFFFFF);
        if (type == 5 && idx < 0x400000) {
            std::lock_guard<std::mutex> lk(g_hook_mutex);
            if (g_literal_uses.size() < 2000000)
                g_literal_uses.push_back({ idx, 0 });
        }
        // call original via trampoline
        using fn_t = uintptr_t(*)(uintptr_t);
        return reinterpret_cast<fn_t>(g_trampoline)(token);
    }

    inline bool make_rwx(void* p, size_t len) {
#ifdef _WIN32
        DWORD old;
        return VirtualProtect(p, len, PAGE_EXECUTE_READWRITE, &old);
#else
        uintptr_t page = reinterpret_cast<uintptr_t>(p) & ~0xFFFULL;
        return mprotect(reinterpret_cast<void*>(page), len + (reinterpret_cast<uintptr_t>(p) - page) + 0x1000,
                        PROT_READ | PROT_WRITE | PROT_EXEC) == 0;
#endif
    }

    inline uintptr_t find_dispatcher() {
        // 1) by name (some builds export the metadata cache symbol)
        if (void* sym = plat::get_proc(plat::get_module(plat::game_assembly_module_name()), "fake_literal_dispatcher"))
            return reinterpret_cast<uintptr_t>(sym);
        if (void* sym = plat::get_proc(plat::get_module(plat::game_assembly_module_name()), "il2cpp_metadata_cache_get_string_literal"))
            return reinterpret_cast<uintptr_t>(sym);
        // 2) signature: push rdi; sub rsp,20h; xor r9d,r9d; mov rdi,rcx; mov ecx,r9d; lock xadd [rdi],rcx
        //    (Unity 2022.2+ win64 MetadataCache dispatcher)
        auto sig = sigz::make::ida("57 48 83 EC 20 45 33 C9 48 89 CF 44 89 C9 F0 0F C1 0F");
        void* hit = sigz::scan_image_first(plat::game_assembly_module_name(), sig);
        if (hit)
            return reinterpret_cast<uintptr_t>(hit);
        // 3) fallback: known RVA for Unity 2022.2+ (V Rising style)
        if (il2cppBase)
            return reinterpret_cast<uintptr_t>(il2cppBase) + 0x167add0;
        return 0;
    }

    inline void dump_dispatcher_bytes() {
        unsigned char b[16];
        std::memcpy(b, reinterpret_cast<void*>(g_target), 16);
        dlog::info("dispatcher bytes: %02x %02x %02x %02x %02x | %02x %02x %02x %02x %02x",
                   b[0],b[1],b[2],b[3],b[4], b[5],b[6],b[7],b[8],b[9]);
        unsigned char s[32];
        std::memcpy(s, reinterpret_cast<void*>(g_trampoline), 32);
        dlog::info("trampoline: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
                   s[0],s[1],s[2],s[3],s[4],s[5],s[6],s[7],s[8],s[9],s[10],s[11],s[12],s[13],s[14],s[15]);
    }

    inline bool install() {
        if (g_hook_active)
            return true;
        g_target = find_dispatcher();
        if (!g_target) {
            dlog::warn("literal dispatcher not found, hook disabled");
            return false;
        }
        dlog::good("hooking literal dispatcher @ 0x%llx", (unsigned long long)g_target);

        std::memcpy(g_original, reinterpret_cast<void*>(g_target), g_stolen);

        // trampoline: stolen bytes + jmp rel32 target+stolen
        unsigned char* tramp = static_cast<unsigned char*>(
#ifdef _WIN32
            VirtualAlloc(nullptr, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
#else
            mmap(nullptr, 64, PROT_READ | PROT_WRITE | PROT_EXEC,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)
#endif
        );
        if (!tramp) {
            dlog::error("hook trampoline alloc failed");
            return false;
        }
        std::memcpy(tramp, g_original, g_stolen);
        tramp[g_stolen] = 0xE9;
        int64_t rel = static_cast<int64_t>(g_target + g_stolen) - (reinterpret_cast<uintptr_t>(tramp) + g_stolen + 5);
        std::memcpy(tramp + g_stolen + 1, &rel, 4);
        g_trampoline = reinterpret_cast<uintptr_t>(tramp);

        // jumpback: mov rax, imm64; jmp rax
        unsigned char* jb = static_cast<unsigned char*>(
#ifdef _WIN32
            VirtualAlloc(nullptr, 32, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
#else
            mmap(nullptr, 32, PROT_READ | PROT_WRITE | PROT_EXEC,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)
#endif
        );
        if (!jb) {
            dlog::error("hook jumpback alloc failed");
            return false;
        }
        jb[0] = 0x48; jb[1] = 0xB8;
        uint64_t dst = g_target + g_stolen;
        std::memcpy(jb + 2, &dst, 8);
        jb[10] = 0xFF; jb[11] = 0xE0;
        g_jumpback = jb;

        // patch target: jmp rel32 to literal_hook_dispatch
        make_rwx(reinterpret_cast<void*>(g_target), 16);
        unsigned char* t = reinterpret_cast<unsigned char*>(g_target);
        t[0] = 0xE9;
        int64_t rel2 = reinterpret_cast<uintptr_t>(&literal_hook_dispatch) - (g_target + 5);
        std::memcpy(t + 1, &rel2, 4);
        g_hook_active = true;
        dlog::good("literal hook installed");
        dump_dispatcher_bytes();
        return true;
    }

    inline void uninstall() {
        if (!g_hook_active)
            return;
        make_rwx(reinterpret_cast<void*>(g_target), 16);
        std::memcpy(reinterpret_cast<void*>(g_target), g_original, g_stolen);
        g_hook_active = false;
    }

    inline size_t use_count() {
        std::lock_guard<std::mutex> lk(g_hook_mutex);
        return g_literal_uses.size();
    }

    inline void take_uses(std::vector<literal_use>& out) {
        std::lock_guard<std::mutex> lk(g_hook_mutex);
        out.swap(g_literal_uses);
    }

}
