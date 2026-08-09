#!/usr/bin/env bash
# run_fake_test.sh — end-to-end test of the dumper against the fake game.
#
# Builds (if needed), sets up a fake game directory (with a fake
# global-metadata.dat), LD_PRELOADs the dumper into the fake game, then
# validates il2cpp_classes.json and il2cpp_strings.json.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$PWD"

cmake -B build/linux -DCMAKE_BUILD_TYPE=Release >/dev/null
cmake --build build/linux -j"$(nproc)" >/dev/null

RUN="$ROOT/build/fake-run"
rm -rf "$RUN"
mkdir -p "$RUN/Fake_Data/il2cpp_data/Metadata"
cp build/linux/fakegame build/linux/GameAssembly.so build/linux/libIl2cppDumperR.so "$RUN/"

# fake global-metadata.dat (v29) whose string literal table matches the fake game
RUN_DIR="$RUN" python3 - <<'EOF'
import struct, os
values = ["player_name", "ui/main_menu", "Hello, world!", "damage",
          "critical_hit", "inventory_full", "level_01", "gg ez"]
blob = b""
defs = b""
for v in values:
    b = v.encode()
    defs += struct.pack("<II", len(b), len(blob))  # {length, dataIndex}
    blob += b
lit_off = 0x100
hdr = struct.pack("<IIIIII", 0xFAB11BAF, 29, lit_off, len(defs), lit_off + len(defs), len(blob))
hdr += b"\0" * (lit_off - len(hdr))
outdir = os.environ.get("RUN_DIR", ".")
out = os.path.join(outdir, "Fake_Data/il2cpp_data/Metadata")
os.makedirs(out, exist_ok=True)
open(os.path.join(out, "global-metadata.dat"), "wb").write(hdr + defs + blob)
EOF

cd "$RUN"
LD_PRELOAD="$RUN/libIl2cppDumperR.so" ./fakegame &
HOST_PID=$!

# wait for the dump (max 15s)
for _ in $(seq 1 150); do
    [ -f il2cpp_classes.json ] && [ -f il2cpp_strings.json ] && break
    sleep 0.1
done
kill $HOST_PID 2>/dev/null || true

echo "== dumper log =="
cat il2cpp_dumper.log || true
echo "================"

python3 - <<'EOF'
import json, sys

classes = json.load(open("il2cpp_classes.json"))
strings = json.load(open("il2cpp_strings.json"))

failures = []
def check(cond, msg):
    if cond: print(f"  ok: {msg}")
    else: failures.append(msg); print(f"  FAIL: {msg}")

player = classes.get("Assembly-CSharp.dll", {}).get("Game", {}).get("Player", {})
check(bool(player), "Player class dumped")
check(player.get("parent") == "Object", "Player parent is Object")
check(any(f.get("name") == "health" and f.get("offset") == 0x10 for f in player.get("fields", [])), "Player.health field @ 0x10")
methods = {m["name"]: m for m in player.get("methods", [])}
check("TakeDamage" in methods, "Player.TakeDamage dumped")
check("offset" in methods.get("TakeDamage", {}), "TakeDamage has method offset")
check(methods.get("TakeDamage", {}).get("param_count") == 1, "TakeDamage param count == 1")
check("offset" not in methods.get("OnRemoved", {}), "abstract OnRemoved has no offset")
props = {p["name"]: p for p in player.get("properties", [])}
check("Health" in props, "Player.Health property dumped")
check(props.get("Health", {}).get("get_method", {}).get("name") == "get_Health", "Health getter bound")
check(props.get("Health", {}).get("set_method", {}).get("name") == "set_Health", "Health setter bound")
check(props.get("Health", {}).get("type") == "System.Int32", "Health type resolved")

obj = classes.get("corlib.dll", {}).get("System", {}).get("Object", {})
check(bool(obj) and "parent" not in obj, "System.Object has no parent")

values = {s.get("value") for s in strings}
for expected in ["player_name", "Hello, world!", "gg ez"]:
    check(expected in values, f"string literal '{expected}' dumped")
check(len(strings) >= 8, f"got {len(strings)} strings (>= 8)")

if failures:
    print(f"\n{len(failures)} FAILURES"); sys.exit(1)
print("\nALL CHECKS PASSED")
EOF
