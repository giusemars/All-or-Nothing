#!/usr/bin/env python3
"""analyze_binary.py - static evidence on a linked PoC binary (rows C3, C4, C5).

For one ELF it reports:

  - the AoN region [__start_aon_text, __stop_aon_text) and the ingress gates
    (every __aon_* symbol) -- absent in a baseline build;
  - every ALIGNED `syscall` (from `objdump -d`), the function it belongs to and
    whether it lies inside the AoN region (C4: P1, P2);
  - every `0f 05` byte pair at ANY offset of the executable segments, split into
    aligned / misaligned and inside / outside the AoN region (C4, and the
    misaligned site of vector B);
  - every `0f 0b` (ud2) byte pair at any offset, split the same way (C3);
  - which of the AoN blocks defined in the library object were linked (C5: D2).

  analyze_binary.py <elf> [<library object>]      -> JSON on stdout
"""
import json
import re
import struct
import subprocess
import sys


def run(*cmd):
    return subprocess.run(cmd, check=True, capture_output=True, text=True).stdout


def symbols(path):
    """name -> address of the defined symbols (nm)."""
    out = {}
    for line in run("nm", path).splitlines():
        parts = line.split()
        if len(parts) == 3:
            out.setdefault(parts[2], int(parts[0], 16))
    return out


def exec_segments(path):
    """(vaddr, bytes) of every executable PT_LOAD segment (ELF64 LE)."""
    data = open(path, "rb").read()
    phoff, = struct.unpack_from("<Q", data, 0x20)
    phentsize, phnum = struct.unpack_from("<HH", data, 0x36)
    segs = []
    for i in range(phnum):
        p_type, p_flags, p_offset, p_vaddr, _, p_filesz = struct.unpack_from(
            "<IIQQQQ", data, phoff + i * phentsize)
        if p_type == 1 and p_flags & 1:  # PT_LOAD, PF_X
            segs.append((p_vaddr, data[p_offset:p_offset + p_filesz]))
    return segs


def byte_pairs(segs, b0, b1):
    hits = []
    for vaddr, blob in segs:
        i = blob.find(bytes([b0, b1]))
        while i >= 0:
            hits.append(vaddr + i)
            i = blob.find(bytes([b0, b1]), i + 1)
    return hits


def aligned_insns(path, mnemonic):
    """(address, enclosing function) of every aligned `mnemonic`."""
    out, func = [], None
    for line in run("objdump", "-d", "--no-show-raw-insn", path).splitlines():
        m = re.match(r"^[0-9a-f]+ <(.+)>:$", line)
        if m:
            func = m.group(1)
            continue
        m = re.match(r"^\s+([0-9a-f]+):\s+(\S+)", line)
        if m and m.group(2) == mnemonic:
            out.append((int(m.group(1), 16), func))
    return out


def main():
    elf = sys.argv[1]
    lib = sys.argv[2] if len(sys.argv) > 2 else None
    syms = symbols(elf)
    lo, hi = syms.get("__start_aon_text"), syms.get("__stop_aon_text")
    gates = sorted((a, n) for n, a in syms.items() if n.startswith("__aon_"))

    def where(addr):
        if lo is None:
            return "no region"
        return "inside" if lo <= addr < hi else "outside"

    def block_of(addr):
        owner = None
        for a, n in gates:
            if a <= addr:
                owner = n
        return owner if where(addr) == "inside" else None

    segs = exec_segments(elf)
    al_sys = aligned_insns(elf, "syscall")
    al_set = {a for a, _ in al_sys}
    al_ud2 = {a for a, _ in aligned_insns(elf, "ud2")}

    funcs = sorted((a, n) for n, a in syms.items()
                   if not n.startswith(("__start_", "__stop_")))

    def sym_off(addr):
        """symbol+offset of the closest preceding symbol."""
        best = None
        for a, n in funcs:
            if a <= addr and (best is None or a >= best[0]):
                best = (a, n)
        return None if best is None else "%s+%d" % (best[1], addr - best[0])

    def classify(hits, aligned):
        return [{"addr": hex(a), "symbol": sym_off(a), "aligned": a in aligned,
                 "where": where(a), "block": block_of(a)} for a in hits]

    res = {
        "binary": elf,
        "region": None if lo is None else [hex(lo), hex(hi)],
        "region_bytes": None if lo is None else hi - lo,
        "ingress_gates": [{"name": n, "addr": hex(a)} for a, n in gates],
        "aligned_syscall": [{"addr": hex(a), "function": f, "where": where(a),
                             "block": block_of(a)} for a, f in al_sys],
        "syscall_byte_pairs": classify(byte_pairs(segs, 0x0f, 0x05), al_set),
        "ud2_byte_pairs": classify(byte_pairs(segs, 0x0f, 0x0b), al_ud2),
    }
    gate_addrs = {a for a, _ in gates}
    res["ud2_in_region_not_gate"] = [
        h for h in res["ud2_byte_pairs"]
        if h["where"] == "inside" and int(h["addr"], 16) not in gate_addrs]
    if lib:
        defined = sorted(n for n in symbols(lib) if n.startswith("__aon_"))
        linked = {n for _, n in gates}
        res["library_blocks"] = [{"block": n, "linked": n in linked}
                                 for n in defined]
    json.dump(res, sys.stdout, indent=2)
    print()


if __name__ == "__main__":
    main()
