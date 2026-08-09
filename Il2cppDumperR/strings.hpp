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
#include <map>
#include <unordered_map>
#include <cstdlib>
#include "state.hpp"
#include "sigz.hpp"
#include "log.hpp"
#include "metadata.hpp"

namespace strdump {

    // MEMORY-ONLY by default: the string literal table is read from process
    // memory. Metadata (global-metadata.dat) is used ONLY to validate the
    // found table and to know its size — never to fabricate string values.
    // Set IL2CPP_STRINGS_ALLOW_METADATA=1 to fill lazily-uncreated literals
    // from the metadata blob.
    inline const bool strings_allow_metadata = []() {
        const char* env = std::getenv("IL2CPP_STRINGS_ALLOW_METADATA");
        if (env && *env == '1')
            return true;
#ifdef IL2CPP_STRINGS_ALLOW_METADATA
        return true;
#else
        return false;
#endif
    }();

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

    inline void* g_found_table = nullptr;

    inline void* find_string_table(const meta::MetadataInfo& metadata) {
        if (auto* t = find_via_signatures(metadata)) { g_found_table = t; return t; }
        dlog::warn("signatures missed, falling back to heuristic scan (slower)");
        g_found_table = find_via_heuristic(metadata);
        return g_found_table;
    }

    inline void dump_strings(const meta::MetadataInfo& metadata) {
        void* table = find_string_table(metadata);
        if (!table) {
            // table not found — memory-only mode has nothing to read
            dlog::error("could not locate the string literal table in memory");
            il2cpp_strings = nlohmann::json::array();
            return;
        }

        il2cpp_strings = nlohmann::json::array();
        size_t from_memory = 0, from_metadata = 0;

        size_t total = metadata.valid && strings_allow_metadata ? metadata.literals.size() : 0x100000;
        if (metadata.valid)
            dlog::info("string literal definitions from metadata: %zu (used for size/validation only)",
                       metadata.literals.size());
        int invalid_run = 0;

        // entries are read in chunks to keep the safe_read syscall count low
        constexpr size_t kChunk = 512;
        std::vector<void*> entries(kChunk);
        for (size_t base = 0; base < total; base += kChunk) {
            size_t n = std::min(kChunk, total - base);
            if (!plat::safe_read(static_cast<void* const*>(table) + base, entries.data(), n * sizeof(void*))) {
                // a failed read may just be a page gap; try entry-by-entry
                for (size_t k = 0; k < n; ++k)
                    entries[k] = table_entry(table, base + k);
            }

            for (size_t k = 0; k < n; ++k) {
                size_t i = base + k;
                void* entry = entries[k];
            if (!entry) {
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
            } else if (strings_allow_metadata && metadata.valid) {
                // not a valid in-memory string; only when explicitly enabled,
                // fall back to the metadata blob
                nlohmann::json jentry;
                jentry["index"] = i;
                jentry["value"] = metadata.literals[i];
                jentry["source"] = "metadata";
                il2cpp_strings.push_back(std::move(jentry));
                ++from_metadata;
            }
            }
        }
        dlog::good("dumped %zu string literals from memory%s",
                   from_memory,
                   from_metadata ? (" + " + std::to_string(from_metadata) + " from metadata").c_str() : "");
    }

    // ---------------------------------------------------------------------
    // String xrefs: find every method that references each string literal.
    //
    // Compiled code loads a literal with:
    //     lea reg, [rip + disp32]          ; disp -> s_StringLiteralTable + index*8
    //   or (older/32-bit-ish)
    //     mov reg, [rip + disp32]
    // and (on modern Unity) the table slot is a pointer, so the actual string is
    // dereferenced via a second load in the same instruction stream.
    //
    // We recover `index` from the displacement relative to the table base and
    // attribute the reference to the function containing the instruction
    // (resolved from the classes dump RVA map).
    // ---------------------------------------------------------------------

    // [start, start+len) -> containing method RVA (best guess from the dump map)
    struct method_map {
        std::vector<std::pair<uint64_t, std::string>> ranges; // {rva_start, "ns.Class::method"}

        void build(const nlohmann::json& classes) {
            for (const auto& [image, nss] : classes.items())
                for (const auto& [ns, clss] : nss.items())
                    for (const auto& [cname, info] : clss.items()) {
                        for (const auto& m : info.value("methods", nlohmann::json::array())) {
                            if (!m.contains("offset"))
                                continue;
                            uint64_t off = m["offset"].get<uint64_t>();
                            std::string label = (ns.empty() ? "" : ns + ".") + cname + "::" +
                                                m.value("name", "?");
                            ranges.push_back({ off, std::move(label) });
                        }
                    }
            std::sort(ranges.begin(), ranges.end(),
                      [](auto& a, auto& b) { return a.first < b.first; });
        }

        // returns the label of the method whose [start,end) window covers `rva`
        std::string containing(uint64_t rva, uint64_t max_len = 0x40000) const {
            auto it = std::upper_bound(ranges.begin(), ranges.end(), rva,
                                       [](uint64_t v, auto& e) { return v < e.first; });
            if (it == ranges.begin())
                return "";
            --it;
            if (rva - it->first < max_len)
                return it->second;
            return "";
        }
    };

    // Scans all executable regions of GameAssembly for RIP-relative references
    // into [table, table + total_literals*8). Returns {rva_of_reference, index}.
    inline std::vector<std::pair<uint64_t, size_t>> find_literal_references(
        void* table, size_t total_literals) {
        uintptr_t table_addr = reinterpret_cast<uintptr_t>(table);
        uintptr_t table_end = table_addr + total_literals * sizeof(void*);
        std::vector<std::pair<uint64_t, size_t>> refs;

        for (auto& r : plat::module_regions(plat::game_assembly_module_name())) {
            if (!r.executable)
                continue;
            auto* p = static_cast<unsigned char*>(r.first);
            auto* end = static_cast<unsigned char*>(r.last);
            for (; p + 7 <= end; ++p) {
                if ((p[0] & 0xF8) != 0x48) // REX.W prefixed load only
                    continue;
                if (p[1] != 0x8B && p[1] != 0x8D) // mov/lea
                    continue;
                if ((p[2] & 0xC7) != 0x05)
                    continue;
                int32_t disp;
                std::memcpy(&disp, p + 3, 4);
                uintptr_t target = reinterpret_cast<uintptr_t>(p) + 7 + disp;
                if (target < table_addr || target >= table_end)
                    continue;
                size_t index = (target - table_addr) / sizeof(void*);
                uint64_t rva = reinterpret_cast<uintptr_t>(p) - reinterpret_cast<uintptr_t>(il2cppBase);
                refs.emplace_back(rva, index);
            }
        }
        return refs;
    }

    // Discovers the s_StringLiteralTable VARIABLE: a writable slot (usually in
    // .bss/.data) whose current value equals the found heap table pointer.
    // Modern il2cpp (2020+) allocates the table on the heap and references it
    // through this slot, so code that loads the slot is a literal use.
    inline void* find_table_slot(void* table) {
        for (auto& r : plat::module_regions(plat::game_assembly_module_name())) {
            if (r.executable)
                continue;
            auto* p = static_cast<unsigned char*>(r.first);
            auto* end = static_cast<unsigned char*>(r.last);
            for (; p + sizeof(void*) <= end; p += sizeof(void*)) {
                void* val = nullptr;
                if (!plat::safe_read(p, val))
                    continue;
                if (val == table)
                    return p;
            }
        }
        return nullptr;
    }

    // Returns RIP-relative reference RVAs to a target address (slot or table).
    inline std::vector<uint64_t> find_rip_refs_to(void* target) {
        uintptr_t addr = reinterpret_cast<uintptr_t>(target);
        std::vector<uint64_t> refs;
        for (auto& r : plat::module_regions(plat::game_assembly_module_name())) {
            if (!r.executable)
                continue;
            auto* p = static_cast<unsigned char*>(r.first);
            auto* end = static_cast<unsigned char*>(r.last);
            for (; p + 7 <= end; ++p) {
                // RIP-relative with ModRM mod=00 r/m=101 (REX may be absent for 32-bit ops)
                unsigned char op = p[0];
                bool rex = (op & 0xF0) == 0x40;
                unsigned char modrm_idx = rex ? 2 : 1;
                if (p + modrm_idx + 5 > end)
                    continue;
                unsigned char opcode = rex ? p[1] : p[0];
                unsigned char modrm = p[modrm_idx];
                if ((modrm & 0xC7) != 0x05) // mod=00 r/m=101
                    continue;
                // mov/lea/cmp/test/inc all fine — any memory operand against the slot
                if (opcode != 0x8B && opcode != 0x8D && opcode != 0x8A && opcode != 0x89 &&
                    opcode != 0x3B && opcode != 0x39 && opcode != 0x85 && opcode != 0xFF &&
                    opcode != 0x83 && opcode != 0xC7) // cmp r/m,imm8 ; mov r/m,imm32
                    continue;
                int32_t disp;
                std::memcpy(&disp, p + modrm_idx + 1, 4);
                uintptr_t tgt = reinterpret_cast<uintptr_t>(p) + modrm_idx + 5 + disp;
                if (tgt != addr)
                    continue;
                uint64_t rva = reinterpret_cast<uintptr_t>(p) - reinterpret_cast<uintptr_t>(il2cppBase);
                refs.push_back(rva);
            }
        }
        return refs;
    }

    // Looks backward from a slot-reference rva for a `mov reg, imm32` that
    // loads the literal index right before the reference. Returns SIZE_MAX if
    // no immediate index is found.
    inline size_t literal_index_near(uint64_t rva) {
        if (!il2cppBase)
            return SIZE_MAX;
        auto* p = reinterpret_cast<unsigned char*>(il2cppBase) + rva;
        for (int back = 0; back < 0x40; ++back) {
            unsigned char* q = p - back;
            if (q < static_cast<unsigned char*>(il2cppBase))
                break;
            // B8+rd imm32 (mov r32, imm32) or 41 B8+rd imm32 (r8d..r15d)
            unsigned char op = q[0];
            if (op >= 0xB8 && op <= 0xBF) {
                uint32_t imm;
                std::memcpy(&imm, q + 1, 4);
                if (imm < 0x400000)
                    return imm;
            }
            if (op == 0x41 && q[1] >= 0xB8 && q[1] <= 0xBF) {
                uint32_t imm;
                std::memcpy(&imm, q + 2, 4);
                if (imm < 0x400000)
                    return imm;
            }
        }
        return SIZE_MAX;
    }

    // Finds a method json by its "ns.Class::method" label. Tries the parsed
    // path first, then a direct string match against the exact label form that
    // method_map uses (handles odd names with dots/backticks/brackets).
    inline nlohmann::json* find_method(const std::string& label) {
        auto dot = label.rfind("::");
        if (dot == std::string::npos)
            return nullptr;
        std::string class_part = label.substr(0, dot);
        std::string method_name = label.substr(dot + 2);
        auto ns_dot = class_part.rfind('.');
        std::string ns = ns_dot == std::string::npos ? "" : class_part.substr(0, ns_dot);
        std::string cname = ns_dot == std::string::npos ? class_part : class_part.substr(ns_dot + 1);

        for (auto& [image, nss] : il2cpp_classes.items())
            for (auto& [ns2, clss] : nss.items()) {
                if (ns2 != ns)
                    continue;
                for (auto& [cname2, info] : clss.items()) {
                    if (cname2 != cname)
                        continue;
                    for (auto& m : info["methods"])
                        if (m.value("name", "") == method_name)
                            return &m;
                }
            }

        // fallback: brute-force the exact label
        for (auto& [image, nss] : il2cpp_classes.items())
            for (auto& [ns2, clss] : nss.items())
                for (auto& [cname2, info] : clss.items())
                    for (auto& m : info["methods"])
                        if (label == (ns2.empty() ? "" : ns2 + ".") + cname2 + "::" + m.value("name", ""))
                            return &m;
        return nullptr;
    }

    // Adds "strings": [...] to every method and "methods": [...] to every
    // string entry based on the reference scan.
    inline void build_string_xrefs(const meta::MetadataInfo& metadata, void* table) {
        size_t total = metadata.valid ? metadata.literals.size() : 0;
        if (!table || total == 0) {
            dlog::warn("string xrefs skipped (no table or no metadata)");
            return;
        }

        method_map mm;
        mm.build(il2cpp_classes);

        // 1) find the runtime table slot (holds the heap table pointer)
        void* slot = find_table_slot(table);
        dlog::info("string table slot: %p", slot);

        std::vector<std::pair<uint64_t, size_t>> refs;
        if (slot) {
            // 2a) code references to the slot -> literal uses (index via the
            //     getter or inline [slot + idx*8]). For each slot reference
            //     site, also look a few instructions ahead for the getter-call
            //     pattern (mov edx,<index>; call GetStringLiteral) and recover
            //     the index from the immediate.
            for (uint64_t rva : find_rip_refs_to(slot)) {
                refs.emplace_back(rva, SIZE_MAX);
                // try to recover a concrete literal index used at this site
                size_t idx = literal_index_near(rva);
                if (idx != SIZE_MAX)
                    refs.emplace_back(rva + 1, idx); // distinct key so it annotates
            }
            // 2b) direct references into the heap table itself (older codegen)
            for (auto& r : find_literal_references(table, total))
                refs.push_back(r);
        } else {
            refs = find_literal_references(table, total);
        }
        dlog::info("found %zu literal reference sites", refs.size());

        // dedupe + map to methods
        std::map<std::string, std::vector<size_t>> strings_by_method;
        std::map<std::string, int> method_ref_count;
        for (const auto& [rva, index] : refs) {
            std::string label = mm.containing(rva);
            dlog::info("  ref rva=0x%llx label='%s'", (unsigned long long)rva, label.c_str());
            std::string key = label.empty() ? ("sub_" + std::to_string(rva)) : label;
            method_ref_count[key]++;
            if (index != SIZE_MAX && index < il2cpp_strings.size())
                strings_by_method[key].push_back(index);
        }

        // annotate methods: add "strings" list (indices with known index) and
        // "string_count" (total refs, incl. indirect via slot)
        for (auto& [label, indices] : strings_by_method) {
            std::sort(indices.begin(), indices.end());
            indices.erase(std::unique(indices.begin(), indices.end()), indices.end());
            auto* m = find_method(label);
            if (!m)
                continue;
            (*m)["strings"] = indices;
        }
        for (auto& [label, count] : method_ref_count) {
            auto* m = find_method(label);
            if (m)
                (*m)["string_count"] = count;
            else
                dlog::info("  xref method not in dump: %s", label.c_str());
        }

        // annotate string entries: "methods" = list of labels that use them
        for (auto& [label, indices] : strings_by_method) {
            for (size_t index : indices) {
                if (index >= il2cpp_strings.size())
                    continue;
                if (!il2cpp_strings[index].contains("methods"))
                    il2cpp_strings[index]["methods"] = nlohmann::json::array();
                il2cpp_strings[index]["methods"].push_back(label);
            }
        }

        dlog::good("string xrefs built: %zu methods reference literals", method_ref_count.size());
    }

}
