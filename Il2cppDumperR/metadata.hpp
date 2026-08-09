#pragma once
// metadata.hpp — minimal reader for global-metadata.dat.
//
// Used for:
//   * il2cpp metadata version detection (multi-version support)
//   * string literal definitions: the exact literal count + expected values,
//     which lets the string-table scanner validate candidates deterministically
//     and fill in literals that il2cpp hasn't lazily created in memory yet.
//
// Header layout (stable from v24 through v31+):
//   0x00 u32 sanity (0xFAB11BAF)
//   0x04 u32 version
//   0x08 u32 stringLiteralOffset
//   0x0C u32 stringLiteralCount   (bytes; /8 = number of definitions)
//   0x10 u32 stringLiteralDataOffset
//   0x14 u32 stringLiteralDataCount (bytes)
//
// Il2CppStringLiteralDefinition field order differs between versions, so we
// auto-detect it: the correct order yields monotonically non-decreasing
// data offsets.

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <fstream>

namespace meta {

    struct MetadataInfo {
        int version = 0;
        std::vector<std::string> literals; // UTF-8, as stored in the blob
        std::string path;
        bool valid = false;
    };

    // Locates <Game>_Data/il2cpp_data/Metadata/global-metadata.dat under game_dir.
    inline std::string find_metadata_file(const std::string& game_dir) {
        auto try_dir = [&](const std::string& data_dir) -> std::string {
            std::string p = data_dir + "/il2cpp_data/Metadata/global-metadata.dat";
            std::ifstream f(p, std::ios::binary);
            return f.good() ? p : "";
        };
#ifdef _WIN32
        WIN32_FIND_DATAA fd;
        HANDLE h = FindFirstFileA((game_dir + "\\*_Data").c_str(), &fd);
        std::string found;
        if (h != INVALID_HANDLE_VALUE) {
            do {
                if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
                    continue;
                found = try_dir(game_dir + "\\" + fd.cFileName);
                if (!found.empty()) break;
            } while (FindNextFileA(h, &fd));
            FindClose(h);
        }
        return found;
#else
        std::string found;
        if (DIR* d = opendir(game_dir.c_str())) {
            while (dirent* e = readdir(d)) {
                std::string name = e->d_name;
                if (name.size() < 5 || name.substr(name.size() - 5) != "_Data")
                    continue;
                found = try_dir(game_dir + "/" + name);
                if (!found.empty()) break;
            }
            closedir(d);
        }
        return found;
#endif
    }

    inline MetadataInfo load(const std::string& game_dir) {
        MetadataInfo info;
        info.path = find_metadata_file(game_dir);
        if (info.path.empty())
            return info;

        std::ifstream f(info.path, std::ios::binary | std::ios::ate);
        if (!f)
            return info;
        size_t size = static_cast<size_t>(f.tellg());
        f.seekg(0);
        if (size < 0x18)
            return info;
        std::vector<char> data(size);
        f.read(data.data(), size);
        if (!f)
            return info;

        auto u32 = [&](size_t off) -> uint32_t {
            uint32_t v;
            std::memcpy(&v, data.data() + off, 4);
            return v;
        };

        if (u32(0) != 0xFAB11BAF)
            return info;
        info.version = static_cast<int>(u32(4));

        uint32_t lit_off = u32(8);
        uint32_t lit_bytes = u32(12);
        uint32_t data_off = u32(16);
        uint32_t data_bytes = u32(20);

        size_t def_count = lit_bytes / 8;
        if (def_count == 0 || def_count > 0x400000 ||
            lit_off + lit_bytes > size || data_off + data_bytes > size)
            return info;

        // Auto-detect Il2CppStringLiteralDefinition field order:
        // candidate A = {length, dataIndex}, candidate B = {dataIndex, length}.
        // The correct one has non-decreasing data offsets.
        auto monotonic_score = [&](bool len_first) -> size_t {
            size_t good = 0;
            uint32_t prev = 0;
            size_t probe = def_count < 64 ? def_count : 64;
            for (size_t i = 0; i < probe; ++i) {
                uint32_t a = u32(lit_off + i * 8);
                uint32_t b = u32(lit_off + i * 8 + 4);
                uint32_t off = len_first ? b : a;
                uint32_t len = len_first ? a : b;
                if (off >= prev && off + len <= data_bytes)
                    ++good;
                prev = off;
            }
            return good;
        };
        bool len_first = monotonic_score(true) >= monotonic_score(false);

        info.literals.reserve(def_count);
        for (size_t i = 0; i < def_count; ++i) {
            uint32_t a = u32(lit_off + i * 8);
            uint32_t b = u32(lit_off + i * 8 + 4);
            uint32_t off = len_first ? b : a;
            uint32_t len = len_first ? a : b;
            if (off + len > data_bytes || len > 0x100000)
                break;
            info.literals.emplace_back(data.data() + data_off + off, len);
        }

        info.valid = !info.literals.empty();
        return info;
    }

}
