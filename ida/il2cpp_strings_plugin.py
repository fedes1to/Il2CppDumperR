# il2cpp_strings_plugin.py — IDA plugin: il2cpp string-literal search, usage
# navigation, and live-use monitoring.
#
# Superset of il2cpp_strings.py (script) + live-hook integration:
#
#   * cached StringDB: loads il2cpp_strings.json + il2cpp_classes.json once,
#     keeps the token scan in memory -> re-searching is instant
#   * search by substring or #index (same as the script)
#   * per-string usage: dump xref data (methods[]), static encoded-token scan,
#     AND live-use counts from the dumper hook (use_count / methods[] entries)
#   * live-use watch: tails il2cpp_live_uses.jsonl written by the dumper's
#     hook while the game runs -> shows real-time (string, method) pairs
#   * hotkey + menu item: Edit -> Plugins -> Il2Cpp String Search (Ctrl+Shift+S)
#   * reload action: re-read dumps + rescan without restarting IDA
#
# Install: copy to %IDADIR%/plugins/ (or ~/.idapro/plugins/) and restart IDA,
# or run as a script: File -> Script file... (works either way).
#
# The JSON files are looked up next to the .i64/.idb (same as il2cpp_import.py).

import json
import os
import threading
import time

import idaapi
import ida_bytes
import ida_funcs
import ida_idaapi
import ida_kernwin
import idautils
import idc

PLUGIN_NAME = "Il2Cpp String Search"
PLUGIN_HOTKEY = "Ctrl+Shift+S"
STRINGS_FILE = "il2cpp_strings.json"
CLASSES_FILE = "il2cpp_classes.json"
LIVE_USES_FILE = "il2cpp_live_uses.jsonl"


# il2cpp string literal token encoding: (5 << 29) | (index << 1) | 1
def encode_token(index):
    return (5 << 29) | (index << 1) | 1


def decode_token(token):
    if (token >> 29) == 5 and (token & 1) == 1:
        return (token >> 1) & 0xFFFFFFF
    return None


def get_idb_path():
    for fn in (getattr(ida_kernwin, "get_idb_path", None),
               getattr(ida_idaapi, "get_idb_path", None),
               getattr(idc, "get_idb_path", None)):
        if fn:
            return fn()
    return ""


class StringDB:
    def __init__(self):
        self.strings = []          # [{index, value, methods?, use_count?}]
        self.by_value = {}         # value -> [indices]
        self.methods = []          # [{rva, name}]
        self.token_hits = {}       # index -> [ea]
        self.scan_done = False
        self.scan_pos = 0
        self.base = 0
        self.live_uses = {}        # (index, method_label) -> count  (live)
        self.live_by_index = {}    # index -> {method_label: count}
        self.live_pos = 0          # file offset in live JSONL
        self.live_path = ""

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

    def set_live_path(self, path):
        self.live_path = path
        self.live_pos = os.path.getsize(path) if path and os.path.exists(path) else 0

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

    def resolve_method_label(self, ret_addr):
        """Map a hook return address (absolute) to a method name."""
        if not ret_addr:
            return ""
        rva = ret_addr - self.base
        return self.method_at(rva)

    def poll_live(self):
        """Tail il2cpp_live_uses.jsonl; ingest any new lines. Returns new-count."""
        if not self.live_path or not os.path.exists(self.live_path):
            return 0
        size = os.path.getsize(self.live_path)
        if size < self.live_pos:
            self.live_pos = 0  # file was rotated
        if size == self.live_pos:
            return 0
        with open(self.live_path, "r", encoding="utf-8") as f:
            f.seek(self.live_pos)
            data = f.read()
            self.live_pos = f.tell()
        n = 0
        for line in data.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                idx = obj.get("index")
                ret = obj.get("ret")
                if idx is None:
                    continue
                label = self.resolve_method_label(ret) if ret else ""
                key = (idx, label)
                self.live_uses[key] = self.live_uses.get(key, 0) + 1
                self.live_by_index.setdefault(idx, {})
                self.live_by_index[idx][label] = self.live_by_index[idx].get(label, 0) + 1
                n += 1
            except Exception:
                continue
        return n

    def live_for(self, index):
        """Live-use breakdown for a literal: {method_label: count}."""
        return self.live_by_index.get(index, {})


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
    """Returns list of method names using `index`: dump xref data, token scan,
    and live-use data (live counts folded in)."""
    methods = {}
    if index < len(db.strings):
        entry = db.strings[index]
        for m in entry.get("methods", []):
            if isinstance(m, dict):
                methods[m.get("method", "?")] = methods.get(m.get("method", "?"), 0) + m.get("count", 1)
            else:
                methods[m] = methods.get(m, 0) + 1
    hits = db.token_hits.get(index, [])
    for ea in hits:
        fn = ida_funcs.get_func(ea)
        if fn:
            rva = fn.start_ea - db.base
            m = db.method_at(rva)
            label = m if m else f"sub_{fn.start_ea - db.base:x}"
            methods[label] = methods.get(label, 0) + 1
    for label, cnt in db.live_for(index).items():
        methods[label] = methods.get(label, 0) + cnt
    return sorted(methods.items(), key=lambda kv: (-kv[1], kv[0]))


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
            use_count = 0
            live = db.live_for(idx)
            if live:
                use_count = sum(live.values())
            elif idx < len(db.strings):
                use_count = db.strings[idx].get("use_count", 0) or 0
            used_by = ", ".join(m for m, _ in usage[:2])
            if use_count:
                used_by += f"  [{use_count}x live]"
            rows.append([str(idx), val[:60].replace("\n", "\\n"), used_by])
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
                live = db.live_for(idx)
                live_str = ""
                if live:
                    live_str = "\n\nLive uses (from hook):\n" + "\n".join(
                        f"  {m}: {c}x" for m, c in sorted(live.items(), key=lambda kv: -kv[1])[:20])
                ida_kernwin.info(f"Literal #{idx}: {val[:200]!r}\n\n"
                                 f"Used by (from dump): {', '.join(m for m, _ in usage) if usage else 'none'}"
                                 f"{live_str}\n\n"
                                 f"Tip: run the dumper with IL2CPP_STRING_HOOK=1 on an active\n"
                                 f"game to capture live per-method usage.")


class il2cpp_strings_plugin_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "Il2Cpp string-literal search & live-use monitor"
    help = "Search il2cpp string literals, show usage sites, watch live hook data"
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_HOTKEY

    def init(self):
        self.db = None
        self.live_timer = None
        self.dirs = []
        self._refresh_dirs()
        idaapi.msg("[il2cpp_strings] plugin ready. Hotkey: %s\n" % PLUGIN_HOTKEY)
        return idaapi.PLUGIN_OK

    def _refresh_dirs(self):
        self.dirs = []
        idb = get_idb_path()
        if idb:
            self.dirs.append(os.path.dirname(idb))
        # also check common dump locations
        for d in ("/tmp", os.path.expanduser("~")):
            if os.path.isdir(d):
                self.dirs.append(d)

    def _find(self, fname):
        for d in self.dirs:
            p = os.path.join(d, fname)
            if os.path.exists(p):
                return p
        return ""

    def _load_or_ask(self):
        if self.db is not None:
            return True
        strings_path = self._find(STRINGS_FILE)
        if not strings_path:
            strings_path = ida_kernwin.ask_file(False, STRINGS_FILE, "Select il2cpp_strings.json")
        if not strings_path:
            return False
        classes_path = self._find(CLASSES_FILE)
        if not classes_path or not os.path.exists(classes_path):
            classes_path = ida_kernwin.ask_file(False, CLASSES_FILE, "Select il2cpp_classes.json")
        db = StringDB()
        db.load(strings_path, classes_path if os.path.exists(classes_path) else None)
        live_path = self._find(LIVE_USES_FILE)
        if live_path:
            db.set_live_path(live_path)
        self.db = db
        self._start_live_timer()
        idaapi.msg("[il2cpp_strings] loaded %d strings, %d methods\n"
                   % (len(db.strings), len(db.methods)))
        return True

    def _start_live_timer(self):
        if self.live_timer is None and self.db and self.db.live_path:
            self.live_timer = idaapi.register_timer(2000, self._poll_live)

    def _poll_live(self):
        if self.db is None:
            return 1
        try:
            n = self.db.poll_live()
            if n:
                idaapi.msg("[il2cpp_strings] +%d live literal uses (total %d)\n"
                           % (n, sum(self.db.live_uses.values())))
        except Exception:
            pass
        return 1  # keep timer

    def _reload(self):
        self.db = None
        if self.live_timer is not None:
            idaapi.unregister_timer(self.live_timer)
            self.live_timer = None
        if self._load_or_ask():
            idaapi.msg("[il2cpp_strings] reloaded\n")

    def run(self, arg):
        if not self._load_or_ask():
            return
        show_search(self.db)

    def term(self):
        if self.live_timer is not None:
            idaapi.unregister_timer(self.live_timer)
            self.live_timer = None


def PLUGIN_ENTRY():
    return il2cpp_strings_plugin_t()


# Allow running as a plain script too (File -> Script file...)
if __name__ == "__main__":
    plugin = il2cpp_strings_plugin_t()
    if plugin.init() != idaapi.PLUGIN_OK:
        raise SystemExit
    plugin.run(0)
    plugin.term()
