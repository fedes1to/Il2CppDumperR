#pragma once
// strings.hpp — recovers il2cpp string literals from process memory.
//
// At runtime il2cpp keeps `s_StringLiteralTable`, an array of Il2CppString*
// built from the string literal blob of global-metadata.dat. There is no
// public API for it, so the table is located by pattern scanning:
//
//   1. a signature DB (per-platform patterns that reference the table through
//      RIP-relative instructions), then
//   2. a generic fallback that tries every RIP-relative instruction in the
//      GameAssembly image and scores each target as a string table.
//
// Newer il2cpp versions create literals LAZILY, so the table is sparse — when
// global-metadata.dat is available we use its string literal definitions both
// to validate candidates deterministically (content match at an index) and to
// fill in not-yet-created entries (tagged "source": "metadata").
//
// All remote reads go through plat::safe_read so a concurrent GC page
// protection flip can't crash the game.

#include <vector>
#include <string>
#include <optional>
#include "state.hpp"
#include "sigz.hpp"
#include "log.hpp"
#include "metadata.hpp"

namespace strdump {

    struct table_sig {
        const char* platform;   // "windows", "linux", or "any"
        const char* note;       // where the sig comes from / unity versions
        const char* pattern;    // IDA-style
        size_t window;          // how many bytes after the match to search for the RIP-rel reference
    };

    // ---------------------------------------------------------------------
    // Signature DB — extend this when adding support for more Unity versions.
    // The scanner takes the pattern match and then tries every instruction
    // inside `window` bytes as a RIP-relative reference to the table.
    // ---------------------------------------------------------------------
    static const table_sig kSignatures[] = {
        // Unity 2019.4 - 2021.x, Windows x64:
        // il2cpp::vm::MetadataCache::InitializeStringLiteralTable
        { "windows", "2019.4-2021.x win64 InitializeStringLiteralTable",
          "48 83 EC 28 48 8B 05 ? ? ? ? 33 D2", 0x60 },
        { "windows", "2019.4-2021.x win64 alt prologue",
          "40 53 48 83 EC 20 48 8B 05 ? ? ? ?", 0x60 },
        // Linux x64 (clang), frame-pointer prologue variant
        { "linux", "2019.4-2021.x linux InitializeStringLiteralTable",
          "55 48 89 E5 53 50 48 8B 05 ? ? ? ?", 0x60 },
        // Linux x64 (clang), red-zone variant
        { "linux", "2019.4-2021.x linux redzone",
          "53 48 83 EC 10 48 8B 05 ? ? ? ?", 0x60 },
    };

    // Header-only view of an Il2CppString read through safe_read.
    struct string_probe {
        void* klass;
        void* monitor;
        int32_t length;
        Il2CppChar first_char; // chars[0]
    };
    static constexpr size_t kCharsOffset = offsetof(string_probe, first_char);

    // Reads a remote Il2CppString and converts it to UTF-8.
    inline std::optional<std::string> read_string_utf8(const void* s, size_t max_len = 0x10000) {
        auto addr = reinterpret_cast<uintptr_t>(s);
        if (!s || (addr & 7) != 0)
            return std::nullopt;
        string_probe probe{};
        if (!plat::safe_read(s, probe))
            return std::nullopt;
        if (probe.klass == nullptr)
            return std::nullopt;
        void* klass_first = nullptr;
        if (!plat::safe_read(probe.klass, klass_first))
            return std::nullopt;
        if (probe.length < 0 || static_cast<size_t>(probe.length) > max_len)
            return std::nullopt;
        size_t len = static_cast<size_t>(probe.length);

        std::vector<Il2CppChar> chars(len + 1, 0);
        const auto* char_base = static_cast<const unsigned char*>(s) + kCharsOffset;
        if (!plat::safe_read(char_base, chars.data(), (len + 1) * sizeof(Il2CppChar)))
            return std::nullopt;
        if (chars[len] != 0) // il2cpp strings are null-terminated
            return std::nullopt;

        std::string value;
        value.reserve(len);
        for (size_t c = 0; c < len; ++c) {
            uint32_t cp = static_cast<uint16_t>(chars[c]);
            if (cp >= 0xD800 && cp <= 0xDBFF && c + 1 < len) {
                uint32_t lo = static_cast<uint16_t>(chars[c + 1]);
                if (lo >= 0xDC00 && lo <= 0xDFFF) {
                    cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                    ++c;
                } else cp = 0xFFFD;
            } else if (cp >= 0xDC00 && cp <= 0xDFFF) cp = 0xFFFD;
            if (cp < 0x80) value.push_back((char)cp);
            else if (cp < 0x800) {
                value.push_back((char)(0xC0 | (cp >> 6)));
                value.push_back((char)(0x80 | (cp & 0x3F)));
            } else if (cp < 0x10000) {
                value.push_back((char)(0xE0 | (cp >> 12)));
                value.push_back((char)(0x80 | ((cp >> 6) & 0x3F)));
                value.push_back((char)(0x80 | (cp & 0x3F)));
            } else {
                value.push_back((char)(0xF0 | (cp >> 18)));
                value.push_back((char)(0x80 | ((cp >> 12) & 0x3F)));
                value.push_back((char)(0x80 | ((cp >> 6) & 0x3F)));
                value.push_back((char)(0x80 | (cp & 0x3F)));
            }
        }
        return value;
    }

    inline bool looks_like_string(const void* s) {
        return read_string_utf8(s).has_value();
    }

    inline void* table_entry(const void* table, size_t i) {
        void* entry = nullptr;
        if (!plat::safe_read(static_cast<void* const*>(table) + i, entry))
            return nullptr;
        return entry;
    }

    // Scores a candidate table (already resolved to the actual array).
    // With metadata: entries whose content matches the expected literal at
    // that index (deterministic). Without: valid strings among the first N
    // entries (sparse tolerant).
    inline size_t score_table_impl(const void* candidate, const meta::MetadataInfo& metadata) {
        if (!candidate)
            return 0;
        // cheap pre-filter: one batched read; most RIP-relative targets in the
        // image don't point at anything resembling a pointer array
        void* batch[16];
        if (!plat::safe_read(candidate, batch, sizeof(batch)))
            return 0;
        int plausible = 0;
        for (auto* e : batch)
            if (e && (reinterpret_cast<uintptr_t>(e) & 7) == 0)
                ++plausible;
        if (plausible < 2)
            return 0;

        size_t score = 0;
        if (metadata.valid) {
            size_t n = metadata.literals.size();
            // sample a spread of indices across the whole table
            for (int k = 0; k < 48; ++k) {
                size_t i = static_cast<size_t>(k) * n / 48;
                if (void* entry = table_entry(candidate, i)) {
                    if (auto value = read_string_utf8(entry)) {
                        if (*value == metadata.literals[i])
                            score += 4;      // exact match: very strong
                        else
                            return 0;        // wrong content: not the literal table
                    }
                }
                // null entries are fine (lazy creation)
            }
            return score;
        }
        for (int i = 0; i < 256; ++i) {
            if (void* entry = table_entry(candidate, i))
                if (looks_like_string(entry))
                    ++score;
        }
        return score;
    }

    // Scores `candidate`, trying both interpretations:
    //   direct   — candidate IS the table (static array in the image)
    //   indirect — candidate is the s_StringLiteralTable VARIABLE (a slot in
    //              .bss holding the heap pointer), the usual case on modern
    //              Unity where the table is CALLOC'd at startup.
    // `resolved` receives the winning table address.
    inline size_t score_table(const void* candidate, const meta::MetadataInfo& metadata, const void*& resolved) {
        resolved = candidate;
        size_t best = score_table_impl(candidate, metadata);
        void* indirect = nullptr;
        if (plat::safe_read(candidate, indirect) && indirect && indirect != candidate) {
            size_t score = score_table_impl(indirect, metadata);
            if (score > best) {
                resolved = indirect;
                return score;
            }
        }
        return best;
    }

    // If the instruction at `p` is a RIP-relative mov/lea (x64), return the
    // absolute target address, else nullptr.
    inline void* rip_relative_target(const unsigned char* p, const unsigned char* region_end) {
        if (p + 7 > region_end)
            return nullptr;
        if ((p[0] & 0xF0) != 0x40 || (p[0] & 0x08) == 0) // REX.W required
            return nullptr;
        if (p[1] != 0x8B && p[1] != 0x8D && p[1] != 0x89) // mov load / lea / mov store
            return nullptr;
        if ((p[2] & 0xC7) != 0x05) // mod=00, r/m=101 => RIP-relative
            return nullptr;
        int32_t disp;
        std::memcpy(&disp, p + 3, 4);
        return const_cast<unsigned char*>(p) + 7 + disp;
    }

    inline void* table_from_code_window(const unsigned char* start, size_t window,
                                        const meta::MetadataInfo& metadata) {
        void* best = nullptr;
        size_t best_score = metadata.valid ? 4 : 4;
        for (size_t off = 0; off + 7 <= window; ++off) {
            void* target = rip_relative_target(start + off, start + window);
            if (!target)
                continue;
            const void* resolved = nullptr;
            size_t score = score_table(target, metadata, resolved);
            if (score > best_score) {
                best = const_cast<void*>(resolved);
                best_score = score;
            }
        }
        return best;
    }

    inline void* find_via_signatures(const meta::MetadataInfo& metadata) {
        const char* mod = plat::game_assembly_module_name();
        for (const auto& sig : kSignatures) {
            if (std::strcmp(sig.platform, "any") != 0 &&
                std::strcmp(sig.platform, plat::platform_name) != 0)
                continue;
            auto pattern = sigz::make::ida(sig.pattern);
            auto hits = sigz::scan_image(mod, pattern, 8);
            for (void* hit : hits) {
                if (auto* table = table_from_code_window(static_cast<unsigned char*>(hit), sig.window, metadata)) {
                    dlog::good("string literal table found via signature (%s)", sig.note);
                    return table;
                }
            }
        }
        return nullptr;
    }

    // Generic fallback: scan the whole GameAssembly image for any RIP-relative
    // reference whose target scores as a string table, keep the best.
    inline void* find_via_heuristic(const meta::MetadataInfo& metadata) {
        void* best = nullptr;
        size_t best_score = 4;
        for (auto& r : plat::module_regions(plat::game_assembly_module_name())) {
            auto* p = static_cast<unsigned char*>(r.first);
            auto* end = static_cast<unsigned char*>(r.last);
            for (; p + 7 <= end; ++p) {
                if ((p[0] & 0xF8) != 0x48) // only REX.W prefixed
                    continue;
                if (void* target = rip_relative_target(p, end)) {
                    const void* resolved = nullptr;
                    size_t score = score_table(target, metadata, resolved);
                    if (score > best_score) {
                        best = const_cast<void*>(resolved);
                        best_score = score;
                    }
                }
            }
        }
        if (best)
            dlog::good("string literal table found via heuristic scan at %p (score %zu)", best, best_score);
        return best;
    }

    inline void* find_string_table(const meta::MetadataInfo& metadata) {
        if (auto* t = find_via_signatures(metadata))
            return t;
        dlog::warn("signatures missed, falling back to heuristic scan (slower)");
        return find_via_heuristic(metadata);
    }

    inline void dump_strings(const meta::MetadataInfo& metadata) {
        void* table = find_string_table(metadata);
        if (!table) {
            if (metadata.valid) {
                // table not found (or never allocated because all literals are
                // lazy) — still deliver every literal from the metadata blob
                dlog::warn("could not locate the string literal table; dumping %zu literals from metadata",
                           metadata.literals.size());
                il2cpp_strings = nlohmann::json::array();
                for (size_t i = 0; i < il2cpp_metadata.literals.size(); ++i) {
                    nlohmann::json jentry;
                    jentry["index"] = i;
                    jentry["value"] = il2cpp_metadata.literals[i];
                    jentry["source"] = "metadata";
                    il2cpp_strings.push_back(std::move(jentry));
                }
            } else {
                dlog::error("could not locate the string literal table");
            }
            return;
        }

        il2cpp_strings = nlohmann::json::array();
        size_t from_memory = 0, from_metadata = 0;

        size_t total = metadata.valid ? metadata.literals.size() : 0x100000;
        int invalid_run = 0;

        // entries are read in chunks to keep the safe_read syscall count low
        constexpr size_t kChunk = 512;
        std::vector<void*> entries(kChunk);
        for (size_t base = 0; base < total; base += kChunk) {
            size_t n = std::min(kChunk, total - base);
            if (!plat::safe_read(static_cast<void* const*>(table) + base, entries.data(), n * sizeof(void*))) {
                if (metadata.valid)
                    break; // table unreadable past this point
                // metadata-less mode: a failed read may just be a page gap
                for (size_t k = 0; k < n; ++k)
                    entries[k] = table_entry(table, base + k);
            }

            for (size_t k = 0; k < n; ++k) {
                size_t i = base + k;
                void* entry = entries[k];
            if (!entry) {
                if (metadata.valid) {
                    // not created in memory (yet) — fall back to the metadata blob
                    nlohmann::json jentry;
                    jentry["index"] = i;
                    jentry["value"] = metadata.literals[i];
                    jentry["source"] = "metadata";
                    il2cpp_strings.push_back(std::move(jentry));
                    ++from_metadata;
                    continue;
                }
                if (++invalid_run > 512)
                    break;
                continue;
            }
            invalid_run = 0;
            if (auto value = read_string_utf8(entry)) {
                nlohmann::json jentry;
                jentry["index"] = i;
                jentry["value"] = std::move(*value);
                jentry["source"] = "memory";
                uintptr_t addr = reinterpret_cast<uintptr_t>(entry);
                if (il2cppBase && addr > reinterpret_cast<uintptr_t>(il2cppBase) &&
                    addr - reinterpret_cast<uintptr_t>(il2cppBase) < 0x10000000)
                    jentry["rva"] = addr - reinterpret_cast<uintptr_t>(il2cppBase);
                il2cpp_strings.push_back(std::move(jentry));
                ++from_memory;
            } else if (metadata.valid) {
                nlohmann::json jentry;
                jentry["index"] = i;
                jentry["value"] = metadata.literals[i];
                jentry["source"] = "metadata";
                il2cpp_strings.push_back(std::move(jentry));
                ++from_metadata;
            }
            }
        }
        dlog::good("dumped %zu string literals (%zu from memory, %zu filled from metadata)",
                   from_memory + from_metadata, from_memory, from_metadata);
    }

}
