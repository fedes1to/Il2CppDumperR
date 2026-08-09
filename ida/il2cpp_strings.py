# il2cpp_strings.py — IDAPython string-literal search & usage navigation.
#
# Companion to il2cpp_import.py. Loads il2cpp_strings.json (+ il2cpp_classes.json)
# produced by Il2CppDumperR, then lets you:
#
#   1. search a string substring -> get its literal index + every method that
#      references it, and jump to the first use (or the metadata string data)
#   2. annotate: mark methods that use literals, and jump between strings and
#      their usage sites
#
# Usage: IDA -> File -> Script file... -> il2cpp_strings.py
# Then: Edit -> Plugins -> Il2Cpp String Search (re-run the script).
#
# It uses xref data from the dump when present (methods[] on string entries
# come from the dumper's static engine or the live-use hook), plus a resumable
# byte scan for encoded literal tokens (5<<29 | idx<<1 | 1) in the image.

import json
import os
import time

import idaapi
import ida_bytes
import ida_funcs
import ida_idaapi
import ida_kernwin
import idautils
import idc

STRINGS_FILE = "il2cpp_strings.json"
CLASSES_FILE = "il2cpp_classes.json"

# il2cpp string literal token encoding: (5 << 29) | (index << 1) | 1
def encode_token(index):
    return (5 << 29) | (index << 1) | 1

def decode_token(token):
    if (token >> 29) == 5 and (token & 1) == 1:
        return (token >> 1) & 0xFFFFFFF
    return None


class StringDB:
    def __init__(self):
        self.strings = []          # [{index, value, methods?, use_count?}]
        self.by_value = {}         # value -> [indices]
        self.methods = []          # [{rva, name}]
        self.token_hits = {}       # index -> [ea]
        self.scan_done = False
        self.scan_pos = 0
        self.base = 0

    def load(self, strings_path, classes_path):
        self.base = idaapi.get_imagebase()
        with open(strings_path, "r", encoding="utf-8") as f:
            self.strings = json.load(f)
        self.by_value = {}
        for s in self.strings:
            self.by_value.setdefault(s.get("value", ""), []).append(s.get("index", 0))
        if classes_path and os.path.exists(classes_path):
            with open(classes_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            for img, nss in data.items():
                for ns, clss in nss.items():
                    for cname, info in clss.items():
                        for m in info.get("methods", []):
                            if "offset" in m:
                                self.methods.append({
                                    "rva": m["offset"],
                                    "name": (ns + "." if ns else "") + cname + "::" + m.get("name", "?"),
                                })
            self.methods.sort(key=lambda x: x["rva"])

    def method_at(self, rva):
        if not self.methods:
            return ""
        import bisect
        rvas = [m["rva"] for m in self.methods]
        i = bisect.bisect_right(rvas, rva) - 1
        if i < 0:
            return ""
        nxt = rvas[i + 1] if i + 1 < len(rvas) else rva + 0x100000
        if rva - rvas[i] < min(nxt - rvas[i], 0x100000):
            return self.methods[i]["name"]
        return ""


def scan_tokens(db, max_bytes=0x4000000, progress=None):
    """Resumable raw-byte scan for encoded literal tokens. Returns True when done."""
    seg = ida_segment.get_segm_by_name(".text")
    if not seg:
        db.scan_done = True
        return True
    start = seg.start_ea
    end = min(seg.end_ea, start + db.scan_pos + max_bytes)
    ea = start + db.scan_pos
    while ea + 4 <= end:
        d = ida_bytes.get_dword(ea)
        idx = decode_token(d)
        if idx is not None:
            b1 = ida_bytes.get_byte(ea - 1) if ea > start else 0
            if (0xB8 <= b1 <= 0xBF) or b1 in (0xC7, 0x68, 0xBE, 0xBF, 0xBA):
                fn = ida_funcs.get_func(ea)
                if fn:
                    db.token_hits.setdefault(idx, []).append(ea)
        ea += 1
    db.scan_pos = ea - start
    if db.scan_pos >= seg.end_ea - start:
        db.scan_done = True
    if progress:
        progress(db.scan_pos, seg.end_ea - start)
    return db.scan_done


def usage_for(db, index):
    """Returns list of method names using `index`: from dump xref data, else
    from the token scan + containing-function heuristic."""
    if index < len(db.strings):
        entry = db.strings[index]
        if entry.get("methods"):
            return entry["methods"]
    hits = db.token_hits.get(index, [])
    methods = set()
    for ea in hits:
        fn = ida_funcs.get_func(ea)
        if fn:
            rva = fn.start_ea - db.base
            m = db.method_at(rva)
            methods.add(m if m else f"sub_{fn.start_ea - db.base:x}")
    return sorted(methods)


def show_search(db):
    if not db.scan_done:
        print("[il2cpp_strings] scanning for encoded literal tokens...")
        def progress(done, total):
            if total and done % max(1, total // 10) < 0x10000:
                print(f"[il2cpp_strings] {done * 100 // total}%")
        while not db.scan_done:
            scan_tokens(db, progress=progress)
            ida_kernwin.refresh_idaview_anyway()
            if ida_kernwin.user_cancelled():
                break
        print(f"[il2cpp_strings] scan done: {len(db.token_hits)} distinct literals found in code")

    while True:
        query = ida_kernwin.ask_str("", 0, "Search string literal (substring, or '#'+index):")
        if not query:
            break
        results = []
        q = query.lower()
        if query.startswith("#"):
            idx = int(query[1:])
            for s in db.strings:
                if s.get("index") == idx:
                    results.append((idx, s.get("value", "")))
                    break
        else:
            for s in db.strings:
                v = s.get("value", "")
                if q in v.lower():
                    results.append((s.get("index", 0), v))
                    if len(results) >= 100:
                        break
        if not results:
            ida_kernwin.info(f"No literals match '{query}'")
            continue

        rows = []
        for idx, val in results[:200]:
            usage = usage_for(db, idx)
            rows.append([str(idx), val[:60].replace("\n", "\\n"), ", ".join(usage[:2])])
        choice = ida_kernwin.choose("Matching strings (double-click to jump)",
                                    [["idx", "value", "used by"], rows], flags=0)
        if choice is not None and 0 <= choice < len(results):
            idx, val = results[choice]
            usage = usage_for(db, idx)
            hits = db.token_hits.get(idx, [])
            if hits:
                ea = hits[0]
                ida_kernwin.jumpto(ea)
                idc.set_cmt(ea, f"il2cpp literal #{idx}: {val[:100]!r}", False)
                print(f"[il2cpp_strings] #{idx} ({val[:40]!r}) first use at 0x{ea:x}")
            else:
                # no code ref in this build: show the string data itself
                ida_kernwin.info(f"Literal #{idx}: {val[:200]!r}\n\n"
                                 f"No direct code reference found in this build.\n"
                                 f"Used by (from dump): {', '.join(usage) if usage else 'none'}\n\n"
                                 f"Tip: run the dumper with IL2CPP_STRING_HOOK=1 on an active\n"
                                 f"game to capture live per-method usage.")


def get_idb_path():
    """IDA 7/8/9 compatible idb path."""
    for fn in (getattr(ida_kernwin, "get_idb_path", None),
               getattr(ida_idaapi, "get_idb_path", None),
               getattr(idc, "get_idb_path", None)):
        if fn:
            return fn()
    return ""


def main():
    idb = get_idb_path()
    d = os.path.dirname(idb) if idb else ""
    strings_path = os.path.join(d, STRINGS_FILE) if d else ""
    classes_path = os.path.join(d, CLASSES_FILE) if d else ""
    if not strings_path or not os.path.exists(strings_path):
        strings_path = ida_kernwin.ask_file(False, STRINGS_FILE, "Select il2cpp_strings.json")
    if not strings_path:
        return
    if not classes_path or not os.path.exists(classes_path):
        classes_path = ida_kernwin.ask_file(False, CLASSES_FILE, "Select il2cpp_classes.json")

    db = StringDB()
    db.load(strings_path, classes_path if os.path.exists(classes_path) else None)
    print(f"[il2cpp_strings] loaded {len(db.strings)} strings, {len(db.methods)} methods")
    show_search(db)


if __name__ == "__main__":
    main()
