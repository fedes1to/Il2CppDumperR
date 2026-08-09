# il2cpp_import.py — IDAPython importer for Il2CppDumperR JSON dumps.
#
# Imports il2cpp_classes.json (and optionally il2cpp_strings.json) produced by
# Il2CppDumperR into an IDA database of GameAssembly.dll / GameAssembly.so:
#
#   * renames methods to Namespace.Class::Method (creates missing functions)
#   * creates a struct per class with its fields at their offsets
#   * sets comments with tokens, return types and signatures
#   * imports string literals into an "il2cpp_str" segment so they are
#     searchable (Alt+T) and renamable
#
# Usage: open GameAssembly in IDA, let autoanalysis finish, then
#   File -> Script file... -> il2cpp_import.py
#
# Tested with IDA 7.7+ / IDA 8.x / IDA 9.x (IDAPython 3).

import json
import re
import time

import idaapi
import ida_bytes
import ida_funcs
import ida_name
import ida_segment
import idc

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

BAD_CHARS = re.compile(r"[^A-Za-z0-9_$]")


def sanitize(name: str, default: str = "unnamed") -> str:
    name = BAD_CHARS.sub("_", name)
    if not name or name[0].isdigit():
        name = "_" + name
    return name or default


def set_name_forced(ea: int, name: str) -> str:
    """Set a name, appending _N on collisions. Returns the final name."""
    if idc.set_name(ea, name, idc.SN_CHECK):
        return name
    for i in range(1, 1000):
        candidate = f"{name}_{i}"
        if idc.set_name(ea, candidate, idc.SN_CHECK):
            return candidate
    return name


def ensure_function(ea: int) -> bool:
    if ida_funcs.get_func(ea):
        return True
    return ida_funcs.add_func(ea)


# map common il2cpp type names to byte sizes for struct members
TYPE_SIZES = {
    "System.Boolean": 1, "System.Byte": 1, "System.SByte": 1, "System.Char": 2,
    "System.Int16": 2, "System.UInt16": 2,
    "System.Int32": 4, "System.UInt32": 4, "System.Single": 4,
    "System.Int64": 8, "System.UInt64": 8, "System.Double": 8,
    "System.IntPtr": 8, "System.UIntPtr": 8,
}


def flag_for_size(size: int):
    if size == 1:
        return idc.FF_BYTE, 1
    if size == 2:
        return idc.FF_WORD, 2
    if size == 4:
        return idc.FF_DWRD, 4
    if size >= 8:
        return idc.FF_QWRD, 8
    return idc.FF_BYTE, size


def get_segm_by_name(name: str) -> int:
    """IDA 7/8/9 compatible segment lookup (returns start ea or BADADDR)."""
    fn = getattr(idc, "get_segm_by_name", None) or getattr(ida_segment, "get_segm_by_name", None)
    seg = fn(name) if fn else None
    if seg is None:
        return idc.BADADDR
    if isinstance(seg, int):
        return seg
    return seg.start_ea


# ---------------------------------------------------------------------------
# classes
# ---------------------------------------------------------------------------

def make_struct(full_name: str, fields: list) -> None:
    sid = idc.add_struc(-1, sanitize(full_name), 0)
    if sid == idc.BADADDR:
        return  # already exists
    prev_end = 0x10  # x64: klass + monitor header
    for field in fields:
        name = sanitize(field.get("name", "field"))
        offset = field.get("offset")
        if offset is None or offset < prev_end:
            continue
        size = TYPE_SIZES.get(field.get("type", ""), 8)  # unknowns are references (pointers)
        flag, fsize = flag_for_size(size)
        idc.add_struc_member(sid, name, offset, flag, None, fsize)
        prev_end = offset + fsize


def import_classes(path: str) -> None:
    print(f"[il2cpp] loading {path} ...")
    t0 = time.time()
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    print(f"[il2cpp] parsed json in {time.time() - t0:.1f}s")

    base = idaapi.get_imagebase()
    n_funcs = n_structs = n_comments = 0

    for image_name, namespaces in data.items():
        for ns_name, classes in namespaces.items():
            for class_name, info in classes.items():
                ns_clean = sanitize(ns_name) if ns_name else ""
                cls_clean = sanitize(class_name)
                prefix = f"{ns_clean}.{cls_clean}" if ns_clean else cls_clean

                fields = info.get("fields") or []
                if fields:
                    make_struct(f"{prefix}_t".replace(".", "_"), fields)
                    n_structs += 1

                for method in info.get("methods") or []:
                    offset = method.get("offset")
                    if offset is None:
                        continue
                    ea = base + offset
                    mname = sanitize(method.get("name", "method"))
                    ensure_function(ea)
                    final = set_name_forced(ea, f"{prefix}::{mname}")
                    n_funcs += 1

                    # comment with the useful bits
                    parts = []
                    if method.get("return_type"):
                        parts.append(method["return_type"])
                    params = method.get("params") or {}
                    if params:
                        plist = [params[k] for k in sorted(params, key=lambda x: int(x))
                                 ] if isinstance(params, dict) else params
                        parts.append("(" + ", ".join(
                            f"{p.get('type', '?')} {p.get('name', '')}".strip()
                            for p in plist) + ")")
                    if method.get("token"):
                        parts.append(f"token 0x{method['token']:08x}")
                    if parts:
                        idc.set_func_cmt(ea, "  ".join(parts), True)
                        n_comments += 1

        print(f"[il2cpp] done image {image_name}: {n_funcs} methods so far")

    print(f"[il2cpp] classes: named {n_funcs} methods, created {n_structs} structs, "
          f"{n_comments} comments in {time.time() - t0:.1f}s")


# ---------------------------------------------------------------------------
# strings
# ---------------------------------------------------------------------------

def import_strings(path: str) -> None:
    print(f"[il2cpp] loading {path} ...")
    with open(path, "r", encoding="utf-8") as f:
        strings = json.load(f)

    # find or create a segment to hold the literals
    seg_ea = get_segm_by_name("il2cpp_str")
    if seg_ea == idc.BADADDR:
        # place after the last segment
        last_end = 0
        for i in range(ida_segment.get_segm_qty()):
            seg = ida_segment.getnseg(i)
            if seg and seg.end_ea > last_end:
                last_end = seg.end_ea
        start = (last_end + 0xFFF) & ~0xFFF
        size = 0x1000
        # pre-compute size: sum of utf-8 bytes + names padding
        size = sum(len(s.get("value", "").encode("utf-8")) + 8 for s in strings)
        size = (size + 0xFFF) & ~0xFFF
        seg = ida_segment.segment_t()
        seg.start_ea = start
        seg.end_ea = start + max(size, 0x10000)
        seg.bitness = 2
        seg.perm = ida_segment.SEGPERM_READ
        ida_segment.add_segm_ex(seg, "il2cpp_str", "DATA", ida_segment.ADDSEG_OR_DIE)

    ea = get_segm_by_name("il2cpp_str")
    if ea == idc.BADADDR:
        print("[il2cpp] failed to create il2cpp_str segment")
        return

    n = 0
    for entry in strings:
        value = entry.get("value", "")
        raw = value.encode("utf-8") + b"\x00"
        if ea + len(raw) >= idc.get_segm_end(ea):
            print(f"[il2cpp] string segment full at {n} strings")
            break
        ida_bytes.put_bytes(ea, raw)
        idc.create_strlit(ea, len(raw))
        set_name_forced(ea, f"sl_{entry.get('index', n)}")
        # keep the literal index visible
        idc.set_cmt(ea, f"il2cpp string literal #{entry.get('index', n)}"
                        + (f" ({entry.get('source')})" if entry.get("source") else ""), False)
        ea += len(raw)
        n += 1

    print(f"[il2cpp] strings: imported {n} literals into 'il2cpp_str' segment")


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main() -> None:
    classes_path = idaapi.ask_file(False, "il2cpp_classes.json", "Select il2cpp_classes.json")
    if not classes_path:
        return
    import_classes(classes_path)

    strings_path = idaapi.ask_file(False, "il2cpp_strings.json | il2cpp_strings.json",
                                   "Select il2cpp_strings.json (cancel to skip)")
    if strings_path:
        import_strings(strings_path)

    print("[il2cpp] import complete")


main()
