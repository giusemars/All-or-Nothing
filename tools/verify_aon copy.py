#!/usr/bin/env python3
"""Build-time verifier: the AoN region of a defended binary has no stray ud2.

Why
---
When a protected thread raises #UD at an address inside the AoN region
[__start_aon_text, __stop_aon_text), aon_mod takes that `ud2` to be an ingress
gate and arms the thread. This coarse "inside the AoN region" test is sound
only if the AoN region contains no `ud2` (the bytes 0f 0b) other than the
ingress gates. A stray 0f 0b -- even a misaligned one, hidden inside the bytes
of another instruction -- would be a second way to arm the thread.

What it checks
--------------
1. From the ELF symbol table it reads:
   - the AoN region bounds __start_aon_text / __stop_aon_text, which ld
     generates around the `aon_text` output section that gathers the linked
     AoN blocks (see aonlibc/aon_syscalls.S);
   - the ingress gates: each __aon_* symbol labels the `ud2` that starts a
     linked AoN block. Only the blocks of the program's required system calls
     survive --gc-sections, so the gates are read per binary, never hardcoded.
2. It tries EVERY byte address of the AoN region, not only instruction
   boundaries, for the pair 0f 0b. Each one found must be an ingress gate;
   any other is a stray ud2 and the check fails.

Usage:  verify_aon.py <binary>
Exit:   0 = no stray ud2, 1 = stray ud2 found, 2 = usage or ELF error.
"""
import struct
import sys
from collections import namedtuple

UD2 = b"\x0f\x0b"

# ---- ELF64 (little-endian x86_64, see elf(5)) ------------------------------
# Only the section header table is read: it locates both the symbol table and
# the file bytes of the AoN region (the `aon_text` section).

# From the ELF header: e_shoff (offset of the section header table),
# e_shentsize and e_shnum (size and number of its entries).
ELF_HEADER = struct.Struct("<40xQ10xHH")

# A section header (Elf64_Shdr), without the sh_ prefix.
SECTION_HEADER = struct.Struct("<IIQQQQIIQQ")
Section = namedtuple("Section", "name type flags addr offset size "
                     "link info addralign entsize")
SHT_SYMTAB = 2   # Section.type of the symbol table (.symtab)

# A symbol (Elf64_Sym): st_name (offset of the name in the string table) and
# st_value (the address); the other fields are skipped.
SYMBOL = struct.Struct("<I4xQ8x")


class VerifyError(Exception):
    """The binary cannot be verified (not ELF64, missing symbol, ...)."""


def read_elf(path):
    """Return the file contents and its section headers."""
    with open(path, "rb") as f:
        data = f.read()
    if data[:4] != b"\x7fELF" or data[4:5] != b"\x02":
        raise VerifyError("not an ELF64 file")
    table_offset, entry_size, entry_count = ELF_HEADER.unpack_from(data)

    # The section header table is an array of `entry_count` headers of
    # `entry_size` bytes each, starting at `table_offset` in the file.
    sections = []
    for i in range(entry_count):
        offset = table_offset + i * entry_size
        fields = SECTION_HEADER.unpack_from(data, offset)
        sections.append(Section(*fields))
    return data, sections


def read_symbols(data, sections):
    """Return {name: address} for every symbol of the symbol table."""
    symtab = next((s for s in sections if s.type == SHT_SYMTAB), None)
    if symtab is None:
        raise VerifyError("no symbol table (stripped binary?)")
    # Symbol names are offsets into the string table the symtab links to.
    strtab = sections[symtab.link]
    symbols = {}
    for off in range(symtab.offset, symtab.offset + symtab.size, symtab.entsize):
        name_off, addr = SYMBOL.unpack_from(data, off)
        start = strtab.offset + name_off
        symbols[data[start:data.index(b"\0", start)].decode()] = addr
    return symbols


def aon_region(symbols):
    """Return the AoN region as the half-open address range (lo, hi)."""
    for name in ("__start_aon_text", "__stop_aon_text"):
        if name not in symbols:
            raise VerifyError("symbol %s not found" % name)
    return symbols["__start_aon_text"], symbols["__stop_aon_text"]


def ingress_gates(symbols):
    """Return the sorted addresses of the ingress gates (the __aon_* symbols)."""
    gates = sorted({addr for name, addr in symbols.items()
                    if name.startswith("__aon_")})
    if not gates:
        raise VerifyError("no __aon_* ingress gate symbols found")
    return gates


def find_ud2(data, sections, lo, hi):
    """Return the address of every 0f 0b whose 0f byte lies in [lo, hi).

    [lo, hi) is exactly the `aon_text` section, so that section's header
    maps each address of the AoN region to its byte in the file.
    """
    aon_text = next((s for s in sections if s.addr == lo and s.size == hi - lo),
                    None)
    if aon_text is None:
        raise VerifyError("no section spans the AoN region")
    # One byte past the region: the 0b of a ud2 whose 0f is its last byte.
    code = data[aon_text.offset:aon_text.offset + aon_text.size + 1]
    return [lo + i for i in range(hi - lo) if code[i:i + 2] == UD2]


def verify(path):
    """Run the check on `path`, print the report, return the exit status."""
    data, sections = read_elf(path)
    symbols = read_symbols(data, sections)
    lo, hi = aon_region(symbols)
    gates = ingress_gates(symbols)

    print("### verify: no stray ud2 in the AoN region "
          "[__start_aon_text,__stop_aon_text) of %s ###" % path)
    print("  AoN region:    [%#x,%#x)" % (lo, hi))
    print("  ingress gates: %s" % " ".join("%#x" % g for g in gates))

    ud2s = find_ud2(data, sections, lo, hi)
    stray = [a for a in ud2s if a not in gates]
    for addr in ud2s:
        if addr in gates:
            print("  ok   ud2 @ %#x  (ingress gate)" % addr)
        else:
            print("  BAD  ud2 @ %#x  (stray: not an ingress gate)" % addr)
    print("verify_aon: %s: %d ud2 in the AoN region (%d ingress gate, %d stray)"
          % (path, len(ud2s), len(ud2s) - len(stray), len(stray)))

    if stray:
        print("verify_aon: FAIL - stray ud2 in the AoN region: aon_mod would "
              "arm a thread that never passed an ingress gate.",
              file=sys.stderr)
        return 1
    # Not a soundness problem (no ud2 too many), but a gate symbol that does
    # not label a ud2 means the gate addresses are wrong.
    missing = [g for g in gates if g not in ud2s]
    if missing:
        print("verify_aon: WARN - no ud2 at ingress gate(s) %s"
              % " ".join("%#x" % g for g in missing), file=sys.stderr)
    print("verify_aon: OK")
    return 0


def main(argv):
    if len(argv) != 2:
        print("usage: %s <binary>" % argv[0], file=sys.stderr)
        return 2
    try:
        return verify(argv[1])
    except (OSError, VerifyError, struct.error, IndexError, ValueError) as e:
        print("verify_aon: %s: %s" % (argv[1], e), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
