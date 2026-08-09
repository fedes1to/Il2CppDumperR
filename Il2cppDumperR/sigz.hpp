#pragma once
// sigz — pattern scanning library.
// Based on upstream https://github.com/creaffy/sigz (updated), extended with a
// portable backend so it works on Windows (VirtualQuery / PE headers) and on
// Linux (/proc/self/maps) for native .so targets.

#include <vector>
#include <string>
#include <string_view>
#include <ranges>
#include <cstring>

#ifdef _WIN32
#include <windows.h>
#else
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <algorithm>
#endif

#define sigz_min(a, b) (((a) < (b)) ? (a) : (b))
#define sigz_max(a, b) (((a) > (b)) ? (a) : (b))

namespace sigz {
    constexpr inline int WILDCARD = -1;
    constexpr inline int NO_LIMIT = -1;

    [[nodiscard]] inline void* scan_unsafe_first(
        void* first,
        void* last,
        const std::vector<int>& pattern
    ) {
        for (unsigned char* ptr = reinterpret_cast<unsigned char*>(first); ptr < reinterpret_cast<unsigned char*>(last) - pattern.size() + 1; ++ptr) {
            bool found = true;
            for (size_t i = 0; i < pattern.size(); ++i) {
                if (pattern[i] == sigz::WILDCARD || ptr[i] == pattern[i])
                    continue;
                found = false;
                break;
            }
            if (found)
                return ptr;
        }
        return nullptr;
    }

    [[nodiscard]] inline std::vector<void*> scan_unsafe(
        void* first,
        void* last,
        const std::vector<int>& pattern,
        size_t limit = sigz::NO_LIMIT
    ) {
        std::vector<void*> results{};
        void* next = first;
        while ((results.size() != limit || limit == sigz::NO_LIMIT) && next < last) {
            void* ptr = sigz::scan_unsafe_first(next, last, pattern);
            if (ptr == nullptr)
                break;
            next = reinterpret_cast<char*>(ptr) + 1;
            results.push_back(ptr);
        }
        return results;
    }

#ifndef _WIN32
    namespace detail {
        struct map_region {
            void* first;
            void* last;
            bool readable;
            std::string path;
        };

        // Parses /proc/self/maps. If `module` is non-empty, only regions backed
        // by a file whose path ends with `module` are returned.
        [[nodiscard]] inline std::vector<map_region> get_regions(std::string_view module = {}) {
            std::vector<map_region> regions{};
            FILE* f = std::fopen("/proc/self/maps", "r");
            if (!f)
                return regions;
            char line[1024];
            while (std::fgets(line, sizeof(line), f)) {
                unsigned long long start = 0, end = 0;
                char perms[8] = {};
                char path[512] = {};
                int fields = std::sscanf(line, "%llx-%llx %7s %*s %*s %*s %511[^\n]", &start, &end, perms, path);
                if (fields < 3)
                    continue;
                if (perms[0] != 'r') // not readable
                    continue;
                if (!module.empty()) {
                    std::string_view p(path);
                    if (p.length() < module.length() || p.substr(p.length() - module.length()) != module)
                        continue;
                }
                regions.push_back({ reinterpret_cast<void*>(start), reinterpret_cast<void*>(end), true, path });
            }
            std::fclose(f);
            return regions;
        }
    }
#endif

    [[nodiscard]] inline std::vector<void*> scan(
        void* first,
        void* last,
        const std::vector<int>& pattern,
        size_t limit = sigz::NO_LIMIT
    ) {
#ifdef _WIN32
        std::vector<MEMORY_BASIC_INFORMATION> regions{};
        MEMORY_BASIC_INFORMATION region_info{};
        for (char* ptr = reinterpret_cast<char*>(first); ptr < reinterpret_cast<char*>(last); ++ptr) {
            if (!VirtualQuery(ptr, &region_info, sizeof(region_info)))
                return {};
            regions.push_back(region_info);
            ptr += region_info.RegionSize;
        }
        size_t remaining = limit;
        std::vector<void*> results{};
        for (auto& region : regions) {
            constexpr DWORD flags1 = PAGE_EXECUTE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE | PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY;
            constexpr DWORD flags2 = PAGE_TARGETS_INVALID | PAGE_GUARD | PAGE_NOCACHE | PAGE_NOACCESS;
            if ((region.State & (MEM_COMMIT | MEM_RESERVE)) == 0 || region.Protect == 0 || (region.Protect & flags1) == 0 || (region.Protect & flags2) != 0)
                continue;
            void* region_first = region.BaseAddress;
            void* region_last = reinterpret_cast<char*>(region.BaseAddress) + region.RegionSize;
            auto region_results = sigz::scan_unsafe(sigz_max(first, region_first), sigz_min(last, region_last), pattern, remaining);
            for (void* ptr : region_results)
                results.push_back(ptr);
            if (region_results.size() != remaining)
                remaining -= region_results.size();
            if (limit != sigz::NO_LIMIT && remaining == 0)
                break;
        }
        return results;
#else
        size_t remaining = limit;
        std::vector<void*> results{};
        for (auto& region : detail::get_regions()) {
            void* region_first = sigz_max(first, region.first);
            void* region_last = sigz_min(last, region.last);
            if (region_first >= region_last)
                continue;
            auto region_results = sigz::scan_unsafe(region_first, region_last, pattern, remaining);
            for (void* ptr : region_results)
                results.push_back(ptr);
            if (region_results.size() != remaining)
                remaining -= region_results.size();
            if (limit != sigz::NO_LIMIT && remaining == 0)
                break;
        }
        return results;
#endif
    }

    [[nodiscard]] inline void* scan_first(
        void* first,
        void* last,
        const std::vector<int>& pattern
    ) {
        std::vector<void*> result = sigz::scan(first, last, pattern, 1);
        return result.empty() ? nullptr : result.front();
    }

    [[nodiscard]] inline std::vector<void*> scan_image(
        std::string_view name,
        const std::vector<int>& pattern,
        size_t limit = sigz::NO_LIMIT
    ) {
#ifdef _WIN32
        char* base = reinterpret_cast<char*>(GetModuleHandleA(name.data()));
        if (!base)
            return {};
        IMAGE_DOS_HEADER* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        IMAGE_NT_HEADERS* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
        return sigz::scan_unsafe(base, base + nt->OptionalHeader.SizeOfImage, pattern, limit);
#else
        std::vector<void*> results{};
        size_t remaining = limit;
        for (auto& region : detail::get_regions(name)) {
            auto region_results = sigz::scan_unsafe(region.first, region.last, pattern, remaining);
            for (void* ptr : region_results)
                results.push_back(ptr);
            if (region_results.size() != remaining)
                remaining -= region_results.size();
            if (limit != sigz::NO_LIMIT && remaining == 0)
                break;
        }
        return results;
#endif
    }

    [[nodiscard]] inline void* scan_image_first(
        std::string_view name,
        const std::vector<int>& pattern
    ) {
        std::vector<void*> result = sigz::scan_image(name, pattern, 1);
        return result.empty() ? nullptr : result.front();
    }

    [[nodiscard]] inline void* scan_process_first(
        const std::vector<int>& pattern
    ) {
#ifdef _WIN32
        SYSTEM_INFO si{};
        GetSystemInfo(&si);
        return sigz::scan_first(si.lpMinimumApplicationAddress, si.lpMaximumApplicationAddress, pattern);
#else
        return sigz::scan_first(nullptr, reinterpret_cast<void*>(UINTPTR_MAX), pattern);
#endif
    }

    [[nodiscard]] inline std::vector<void*> scan_process(
        const std::vector<int>& pattern,
        size_t limit = sigz::NO_LIMIT
    ) {
#ifdef _WIN32
        SYSTEM_INFO si{};
        GetSystemInfo(&si);
        return sigz::scan(si.lpMinimumApplicationAddress, si.lpMaximumApplicationAddress, pattern, limit);
#else
        return sigz::scan(nullptr, reinterpret_cast<void*>(UINTPTR_MAX), pattern, limit);
#endif
    }

    namespace make {
        [[nodiscard]] inline std::vector<int> ida(
            std::string_view pattern
        ) {
            std::vector<int> result{};
            for (auto&& token : std::ranges::split_view(pattern, ' ') | std::views::transform([](auto e) { return std::string_view(e); }))
                result.push_back(token == "?" ? sigz::WILDCARD : std::stoi(std::string(token), nullptr, 16));
            return result;
        }

        [[nodiscard]] inline std::vector<int> x64dbg(
            std::string_view pattern
        ) {
            std::vector<int> result{};
            for (auto&& token : std::ranges::split_view(pattern, ' ') | std::views::transform([](auto e) { return std::string_view(e); }))
                result.push_back(token == "??" ? sigz::WILDCARD : std::stoi(std::string(token), nullptr, 16));
            return result;
        }

        [[nodiscard]] inline std::vector<int> string(
            std::string_view str,
            bool null = true
        ) {
            return std::vector<int>(str.begin(), null ? str.end() + 1 : str.end());
        }

        [[nodiscard]] inline std::vector<int> string(
            std::wstring_view str,
            bool null = true
        ) {
            const char* first = reinterpret_cast<const char*>(&*str.begin());
            const char* last = reinterpret_cast<const char*>(&*str.end());
            return std::vector<int>(first, null ? last + sizeof(wchar_t) : last);
        }

        template <class T>
        [[nodiscard]] inline std::vector<int> value(
            const T& data
        ) {
            return std::vector<int>(reinterpret_cast<const char*>(&data), reinterpret_cast<const char*>(&data) + sizeof(T));
        }
    }
}
