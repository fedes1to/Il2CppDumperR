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


    // C++ logger called from the raw-byte stub. The stub captures the token
    // (ABI arg) and the game's return address, calls this, then tail-jumps to
    // target+5 with the stack EXACTLY as the stolen prologue (`push rdi;
    // sub rsp,20h`) would leave it — so the original function body runs
    // correctly and returns to the game.
    extern "C" void literal_hook_c(uint32_t token, uintptr_t ret_addr) {
        FILE* df = std::fopen("/tmp/hook_called.log", "a");
        if (df) { std::fprintf(df, "C called token=0x%x ret=%p\n", token, (void*)ret_addr); std::fclose(df); }
        uint32_t type = token >> 29;
        uint32_t idx = (token >> 1) & 0xFFFFFFF;
        if (type == 5 && idx < 0x400000) {
            std::lock_guard<std::mutex> lk(g_hook_mutex);
            if (g_literal_uses.size() < 2000000)
                g_literal_uses.push_back({ idx, ret_addr });
        }
    }

    // Raw-byte stub (works for MinGW/GCC/Linux, no naked asm). At entry the
    // stack is [rsp]=game's retaddr (the dispatcher was CALLED). We replay the
    // stolen prologue, call the logger, then tail-jmp to target+5 via
    // g_jumpback (mov rax,imm64; jmp rax). Stack stays 0x28 below entry:
    // push rdi (8) + sub rsp,20h (32) = 40 = 0x28, matching the prologue.
    //
    //   push rdi                 ; 57
    //   sub rsp, 0x20            ; 48 83 EC 20
    //   mov eax, edi             ; 89 F8      (SysV: token in edi)
    //   mov rsi, [rsp+0x28]      ; 48 8B 74 24 28  (retaddr -> 2nd arg)
    //   call literal_hook_c      ; E8 rel32
    //   jmp [rip+0]              ; FF 25 00 00 00 00 -> g_jumpback
    //   <8-byte g_jumpback ptr>
#ifdef _WIN32
    inline unsigned char literal_hook_stub_bytes[64] = {
        0x57,                                             // push rdi
        0x48, 0x83, 0xEC, 0x20,                           // sub rsp,20h
        0x89, 0xC8,                                       // mov eax,ecx (win: token in ecx)
        0x48, 0x8B, 0x94, 0x24, 0x28, 0x00, 0x00, 0x00,   // mov rdx,[rsp+28h]
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rax, imm64 (count)
        0x48, 0xFF, 0xC0,                                 // inc rax
        0x48, 0xA3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov [imm64], rax (count)
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,               // jmp [rip+0]
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   // g_jumpback ptr (37)
    };
    static constexpr int kJumpbackOff = 37;
    static constexpr int kCountReadOff = 16;   // mov rax,imm64 -> imm at 16-23
    static constexpr int kCountWriteOff = 28;  // mov [imm64],rax -> imm at 28-35
    inline std::atomic<uint64_t> g_hook_count{0};
#else
    inline unsigned char literal_hook_stub_bytes[64] = {
        0x57,                                             // push rdi
        0x48, 0x83, 0xEC, 0x20,                           // sub rsp,20h
        0x89, 0xF8,                                       // mov eax,edi
        0x48, 0x8B, 0x74, 0x24, 0x28,                     // mov rsi,[rsp+28h]  (7-11)
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rax,imm64     (12-21, imm at 14)
        0x48, 0xFF, 0xC0,                                 // inc rax           (22-23)
        0x48, 0x89, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov [imm64],rax   (25-28 op, imm at 29-36)
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,               // jmp [rip+0]       (37-42, reads [43])
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   // g_jumpback ptr    (43-50)
    };
    static constexpr int kJumpbackOff = 43;
    static constexpr int kCountReadOff = 14;
    static constexpr int kCountWriteOff = 29;
    inline std::atomic<uint64_t> g_hook_count{0};
#endif

    inline uintptr_t setup_stub_exec() {
        unsigned char* mem = static_cast<unsigned char*>(
#ifdef _WIN32
            VirtualAlloc(nullptr, sizeof(literal_hook_stub_bytes), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
#else
            mmap(nullptr, sizeof(literal_hook_stub_bytes), PROT_READ | PROT_WRITE | PROT_EXEC,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)
#endif
        );
        if (!mem)
            return 0;
        std::memcpy(mem, literal_hook_stub_bytes, sizeof(literal_hook_stub_bytes));
        // patch mov rax,imm64 (count) and mov [imm64],rax (count) and jmp target
        uint64_t count_addr = reinterpret_cast<uintptr_t>(&g_hook_count);
        uint64_t jb_addr = reinterpret_cast<uintptr_t>(g_jumpback);
        std::memcpy(mem + kCountReadOff, &count_addr, 8);
        std::memcpy(mem + kCountWriteOff, &count_addr, 8);
        std::memcpy(mem + kJumpbackOff, &jb_addr, 8);

        return reinterpret_cast<uintptr_t>(mem);
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
        // 1) signature: push rdi; sub rsp,20h; xor r9d,r9d; mov rdi,rcx; mov ecx,r9d; lock xadd [rdi],rcx
        //    (Unity 2022.2+ win64 MetadataCache dispatcher)
        auto sig = sigz::make::ida("57 48 83 EC 20 45 33 C9 48 89 CF 44 89 C9 F0 0F C1 0F");
        if (void* hit = sigz::scan_image_first(plat::game_assembly_module_name(), sig))
            return reinterpret_cast<uintptr_t>(hit);
        // 1b) simpler prologue (fake/test builds): push rdi; sub rsp,20h; call
        auto sig2 = sigz::make::ida("57 48 83 EC 20 E8");
        if (void* hit = sigz::scan_image_first(plat::game_assembly_module_name(), sig2))
            return reinterpret_cast<uintptr_t>(hit);
        // 2) by name (some builds export the metadata cache symbol)
        if (void* sym = plat::get_proc(plat::get_module(plat::game_assembly_module_name()), "il2cpp_metadata_cache_get_string_literal"))
            return reinterpret_cast<uintptr_t>(sym);
        // 3) fallback: known RVA for Unity 2022.2+ (V Rising style)
        if (il2cppBase)
            return reinterpret_cast<uintptr_t>(il2cppBase) + 0x167add0;
        return 0;
    }

    inline void dump_dispatcher_bytes() {
        unsigned char b[16];
        std::memcpy(b, reinterpret_cast<void*>(g_target), 16);
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

        // patch target: jmp rel32 to the executable stub
        uintptr_t stub = setup_stub_exec();
        dlog::info("hook stub @ 0x%llx", (unsigned long long)stub);
        make_rwx(reinterpret_cast<void*>(g_target), 16);
        unsigned char* t = reinterpret_cast<unsigned char*>(g_target);
        t[0] = 0xE9;
        int64_t rel2 = stub - (g_target + 5);
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
