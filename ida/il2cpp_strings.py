# il2cpp_strings.py — IDAPython string-literal search & xref navigation.
#
# Companion to il2cpp_import.py. Loads il2cpp_strings.json + il2cpp_classes.json
# produced by Il2CppDumperR, then lets you:
#
#   1. search a string substring -> get its literal index + every method that
#      references it, and jump to the first use
#   2. annotate the image: mark every literal's usage sites (methods) so you
#      can see at a glance where strings are used
#
# Usage: IDA -> File -> Script file... -> il2cpp_strings.py
# Then: Edit -> Plugins -> Il2Cpp String Search (or run again).

import json
import os
import time

import idaapi
import ida_bytes
import ida_funcs
import ida_kernwin
import idautils
import idc

STRINGS_FILE = "il2cpp_strings.json"
CLASSES_FILE = "il2cpp_classes.json"

# il2cpp string literal token: (type=5) << 29 | (index << 1) | 1
def encode_token(index: int) -> int:
    return (5 << 29) | (index << 1) | 1

def decode_token(token: int):
    if (token >> 29) == 5 and (token & 1) == 1:
        return (token >> 1) & 0xFFFFFFF
    return None


class StringDB:
    def __init__(self):
        self.strings = []           # [{index, value}]
        self.by_value = {}          # value -> [indices]
        self.methods = []           # [{rva, name}]
        self.token_hits = {}        # index -> [insn_ea]
        self.scan_pos = 0           # resumable scan offset (rva)
        self.scan_done = False
        self.strings_path = None
        self.classes_path = None

    def load(self, strings_path, classes_path):
        self.strings_path = strings_path
        self.classes_path = classes_path
        with open(strings_path, "r", encoding="utf-8") as f:
            self.strings = json.load(f)
        self.by_value = {}
        for s in self.strings:
            self.by_value.setdefault(s.get("value", ""), []).append(s.get("index", 0))
        if classes_path and os.path.exists(classes_path):
            with open(classes_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.methods = []
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
        return True

    def method_at(self, rva):
        import bisect
        rvas = [m["rva"] for m in self.methods]
        i = bisect.bisect_right(rvas, rva) - 1
        if i < 0:
            return ""
        nxt = rvas[i + 1] if i + 1 < len(rvas) else rva + 0x100000
        if rva - rvas[i] < min(nxt - rvas[i], 0x100000):
            return self.methods[i]["name"]
        return ""


def scan_tokens(db: StringDB, imagebase: int, max_bytes=0x4000000, progress=None):
    """Fast raw-byte scan for encoded literal tokens, verifying each hit is a
    plausible immediate operand. Resumable via db.scan_pos. max_bytes caps a
    single call; call repeatedly to finish. Returns True when done."""
    seg = ida_segment.get_segm_by_name(".text")
    if not seg:
        db.scan_done = True
        return True
    start = seg.start_ea
    end = min(seg.end_ea, start + db.scan_pos + max_bytes)
    t0 = time.time()
    n = 0
    ea = start + db.scan_pos
    while ea + 4 <= end:
        d = ida_bytes.get_dword(ea)
        idx = decode_token(d)
        if idx is not None and (idx >> 24) == 0:  # index < 16M
            # plausible immediate positions: B8+rd imm32 / C7 / 41 B8+rd
            b1 = ida_bytes.get_byte(ea - 1) if ea > start else 0
            if (0xB8 <= b1 <= 0xBF) or b1 in (0xC7, 0x68, 0xBE, 0xBF, 0xBA):
                fn = ida_funcs.get_func(ea)
                if fn:
                    db.token_hits.setdefault(idx, []).append(ea)
                    n += 1
        ea += 1
    db.scan_pos = ea - start
    if db.scan_pos >= seg.end_ea - start:
        db.scan_done = True
    if progress:
        progress(db.scan_pos, seg.end_ea - start)
    return db.scan_done


def build_method_hits(db: StringDB):
    """Converts token_hits (byte offsets) to {index: [method names]} using the
    containing-function heuristic."""
    base = idaapi.get_imagebase()
    out = {}
    for idx, addrs in db.token_hits.items():
        methods = set()
        for ea in addrs:
            fn = ida_funcs.get_func(ea)
            if fn:
                rva = fn.start_ea - base
                m = db.method_at(rva) if db.methods else ""
                methods.add(m if m else f"sub_{fn.start_ea - base:x}")
        out[idx] = sorted(methods)
    return out


def do_search(db: StringDB, query: str, method_hits=None, limit=100):
    q = query.lower()
    out = []
    for s in db.strings:
        v = s.get("value", "")
        idx = s.get("index", 0)
        if q in v.lower() or (query.isdigit() and idx == int(query)):
            methods = (method_hits or {}).get(idx, [])
            out.append((idx, v, methods))
            if len(out) >= limit:
                break
    return out


def show_search(db: StringDB, method_hits):
    if not method_hits:
        ida_kernwin.info("No string-literal usage data found.\n\n"
                         "The scan found no encoded literal tokens in this binary.\n"
                         "This is normal for stripped/dedicated-server builds — the\n"
                         "dumper's runtime hook (IL2CPP_STRING_HOOK=1) captures live\n"
                         "uses instead. You can still search strings and jump to the\n"
                         "metadata index.")
    while True:
        query = ida_kernwin.ask_str("", 0, "Search string literal (substring):")
        if not query:
            break
        results = do_search(db, query, method_hits)
        if not results:
            ida_kernwin.info(f"No literals match '{query}'")
            continue
        rows = [[str(r[0]), r[1][:60].replace("\n", "\\n"), ", ".join(r[2][:3])] for r in results[:200]]
        choice = ida_kernwin.choose("Matching strings (double-click to jump)",
                                    [["idx", "value", "methods"], rows], flags=0)
        if choice is not None and 0 <= choice < len(results):
            idx, val, methods = results[choice]
            hits = db.token_hits.get(idx, [])
            if hits:
                ea = hits[0]
                ida_kernwin.jumpto(ea)
                idc.set_cmt(ea, f"il2cpp literal #{idx}: {val[:100]!r}", False)
                print(f"[il2cpp_strings] literal #{idx} ({val[:40]!r}) first use at 0x{ea:x}")
            else:
                ida_kernwin.info(f"Literal #{idx} ({val[:40]!r}) has no direct code refs in this build")


def main():
    base = idaapi.get_imagebase()
    idb = ida_kernwin.get_idb_path()
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

    # resumable scan with progress (keep the UI alive)
    def progress(done, total):
        if done % (total // 10) < 0x10000:
            print(f"[il2cpp_strings] scanning {done * 100 // total}%...")

    print("[il2cpp_strings] scanning for encoded literal tokens...")
    while not db.scan_done:
        scan_tokens(db, base, max_bytes=0x4000000, progress=progress)
        ida_kernwin.refresh_idaview_anyway()
        if ida_kernwin.user_cancelled():
            break
    print(f"[il2cpp_strings] scan done: {sum(len(v) for v in db.token_hits.values())} hits "
          f"across {len(db.token_hits)} distinct literals")

    method_hits = build_method_hits(db)
    show_search(db, method_hits)


main()
