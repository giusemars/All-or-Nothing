#!/usr/bin/env python3
"""Build-time verifier: the AoN region of a defended binary has no stray ud2.

Usage:  verify_aon.py <binary>
Exit:   0 = no stray ud2, 1 = stray ud2 found, 2 = usage or ELF error.

What it checks
--------------
Every `ud2` (the bytes 0f 0b, at any offset, aligned or misaligned) inside
the AoN region [__start_aon_text, __stop_aon_text) is an ingress gate.

What it does
------------
1. Read the whole file and check that it is an ELF64 file.
2. Read the section headers (ElfFile._read_sections); the ELF header says
   where they are.
3. Find the symbol table (.symtab) and read every symbol, taking each name
   from the string table it links to (ElfFile._read_symbols).
4. Look up the AoN region bounds: the addresses of __start_aon_text and
   __stop_aon_text, which ld generates around the `aon_text` section.
5. Collect the ingress gates: the addresses of the __aon_* symbols, one per
   AoN block linked into this binary (only the wrappers of its required
   system calls survive --gc-sections).
6. Find the section that spans exactly the AoN region (`aon_text`) and take
   the region's bytes from the file.
7. Try every byte address of the region for 0f 0b (AonRegion.find_ud2).
8. Report each ud2 found: at an ingress gate it is ok, anywhere else it is
   stray. Warn if an ingress gate has no ud2.
9. Exit 1 if any ud2 is stray, 0 otherwise.

Why
---
When a protected thread raises #UD at an address inside the AoN region
[__start_aon_text, __stop_aon_text), aon_mod takes that `ud2` to be an ingress
gate and arms the thread. This coarse "inside the AoN region" test is sound
only if the AoN region contains no `ud2` (the bytes 0f 0b) other than the
ingress gates. A stray 0f 0b -- even a misaligned one, hidden inside the bytes
of another instruction -- would be a second way to arm the thread.
"""
import sys
from dataclasses import dataclass

UD2 = b"\x0f\x0b"


class VerifyError(Exception):
    """The binary cannot be verified (not ELF64, missing symbol, ...)."""


# ---- Reading raw ELF64 fields (little-endian x86_64, see elf(5)) -----------

def read_int(data, offset, size):
    """Read the little-endian unsigned integer of `size` bytes at `offset`."""
    return int.from_bytes(data[offset:offset + size], "little")


def read_string(data, offset):
    """Read the NUL-terminated string at `offset`."""
    end = data.index(b"\0", offset)
    return data[offset:end].decode()


# ---- ELF objects -----------------------------------------------------------

@dataclass
class Section:
    """One section of the file, as described by its section header
    (Elf64_Shdr). Only the fields this tool needs are kept."""
    index: int    # position in the section header table
    type: int     # sh_type: what the section holds (SYMTAB below)
    addr: int     # sh_addr: address of the section in memory
    offset: int   # sh_offset: position of its bytes in the file
    size: int     # sh_size: number of bytes
    link: int     # sh_link: index of a related section
    entsize: int  # sh_entsize: size of one entry, if it is a table

    SYMTAB = 2    # sh_type of the symbol table (.symtab)


def read_section(data, index, header):
    """Read the section header that starts at file offset `header`."""
    return Section(index=index,
                   type=read_int(data, header + 4, 4),
                   addr=read_int(data, header + 16, 8),
                   offset=read_int(data, header + 24, 8),
                   size=read_int(data, header + 32, 8),
                   link=read_int(data, header + 40, 4),
                   entsize=read_int(data, header + 56, 8))


@dataclass
class Symbol:
    """One entry of the symbol table (Elf64_Sym): a name for an address."""
    name: str
    address: int


def read_symbol(data, entry, string_table):
    """Read the symbol that starts at file offset `entry`.

    The entry does not hold the name itself, only the offset of the name
    in `string_table`, the section that stores all the symbol names one
    after the other, each ended by a NUL byte.
    """
    name_offset = read_int(data, entry + 0, 4)   # st_name
    address = read_int(data, entry + 8, 8)       # st_value
    return Symbol(name=read_string(data, string_table.offset + name_offset),
                  address=address)


class ElfFile:
    """An ELF64 file: its bytes, its sections and its symbols."""

    def __init__(self, path):
        with open(path, "rb") as f:
            self.data = f.read()
        if self.data[:4] != b"\x7fELF" or self.data[4:5] != b"\x02":
            raise VerifyError("not an ELF64 file")
        self.sections = self._read_sections()
        self.symbols = self._read_symbols()

    def _read_sections(self):
        """Read the section header table: an array of `count` headers of
        `entry_size` bytes, starting at `table` (fields of the ELF header)."""
        table = read_int(self.data, 0x28, 8)        # e_shoff
        entry_size = read_int(self.data, 0x3a, 2)   # e_shentsize
        count = read_int(self.data, 0x3c, 2)        # e_shnum
        return [read_section(self.data, i, table + i * entry_size)
                for i in range(count)]

    def _read_symbols(self):
        """Read the symbol table: an array of `entsize`-byte symbols."""
        symtabs = [s for s in self.sections if s.type == Section.SYMTAB]
        if not symtabs:
            raise VerifyError("no symbol table (stripped binary?)")
        symtab = symtabs[0]
        # symtab.link is the index of the section holding the symbol names.
        string_table = self.sections[symtab.link]
        return [read_symbol(self.data, symtab.offset + i * symtab.entsize,
                            string_table)
                for i in range(symtab.size // symtab.entsize)]

    def address_of(self, name):
        """Return the address of the symbol `name`."""
        for symbol in self.symbols:
            if symbol.name == name:
                return symbol.address
        raise VerifyError("symbol %s not found" % name)


class AonRegion:
    """The AoN region [__start_aon_text, __stop_aon_text) of a defended
    binary: its bounds, its ingress gates and its bytes."""

    def __init__(self, elf):
        self.lo = elf.address_of("__start_aon_text")
        self.hi = elf.address_of("__stop_aon_text")

        # Each __aon_* symbol labels the ud2 ingress gate of an AoN block.
        self.gates = sorted({s.address for s in elf.symbols
                             if s.name.startswith("__aon_")})
        if not self.gates:
            raise VerifyError("no __aon_* ingress gate symbols found")

        # The region is exactly the `aon_text` section, whose header gives
        # where the region's bytes are in the file.
        spanning = [s for s in elf.sections
                    if s.addr == self.lo and s.size == self.hi - self.lo]
        if not spanning:
            raise VerifyError("no section spans the AoN region")
        start = spanning[0].offset
        # One byte past the region: the 0b of a ud2 whose 0f is its last byte.
        self.code = elf.data[start:start + (self.hi - self.lo) + 1]

    def find_ud2(self):
        """Return the address of every 0f 0b whose 0f byte is in the region,
        trying every byte, not only instruction boundaries."""
        return [self.lo + i for i in range(self.hi - self.lo)
                if self.code[i:i + 2] == UD2]


# ---- The check -------------------------------------------------------------

def verify(path):
    """Run the check on `path`, print the report, return the exit status."""
    region = AonRegion(ElfFile(path))

    print("### verify: no stray ud2 in the AoN region "
          "[__start_aon_text,__stop_aon_text) of %s ###" % path)
    print("  AoN region:    [%#x,%#x)" % (region.lo, region.hi))
    print("  ingress gates: %s" % " ".join("%#x" % g for g in region.gates))

    ud2s = region.find_ud2()
    stray = [a for a in ud2s if a not in region.gates]
    for addr in ud2s:
        if addr in region.gates:
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
    missing = [g for g in region.gates if g not in ud2s]
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
    except (OSError, VerifyError, IndexError, ValueError) as e:
        print("verify_aon: %s: %s" % (argv[1], e), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
