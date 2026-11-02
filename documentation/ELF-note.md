# The AoN ELF note

**Background.** An *AoN block* is a short instruction sequence that a thread must run from its first instruction, never from the middle. In this PoC each system call wrapper is one: `ud2 ; mov $nr,%eax ; syscall`, followed by a `ret`.

- `ud2` is the **ingress gate**. It raises #UD, the invalid-opcode fault; the kernel module (`aon_mod`) catches it, **arms** the thread (records that it entered a block) and resumes it after the `ud2`.
- `syscall` is the **egress gate**. The module allows the system call only if the thread is armed, and disarms it.FF
- The **AoN region** is the address range holding all the linked AoN blocks. The linker puts them in one *section* (a named piece of the executable, see section 1), `aon_text`, and marks its bounds with two *symbols* (names for addresses), `__start_aon_text` and `__stop_aon_text`. A `syscall` outside this range is refused.

So the module must know each program's AoN region. The program carries it in an **ELF note**, a small tagged record inside the executable, named `.note.aon`. A program built with the AoN blocks and the note is a **defended** build. A separate **build-time verifier**, `tools/verify_aon.py`, checks that its region contains no `ud2` other than the ingress gates.

This guide explains:

- the parts of ELF involved (sections 1–2)
- the note (3) and how it is produced (4)
- how the kernel module (5) and the verifier (6) each find the region
- a comparison of the two (7) and the commands to inspect all of this in a real binary (8)

## 1. What an ELF is

ELF (*Executable and Linkable Format*) is the file format Linux uses for object files, executables and shared libraries.

### Layout

A ELF file has four parts:

| # | Part                     | What it holds                                                                                           | Starts at              | Size                 |
|---|--------------------------|---------------------------------------------------------------------------------------------------------|------------------------|----------------------|
| 1 | **ELF header**           | identity of the file and where the two tables are (see below)                                           | always `0`             | 64 bytes             |
| 2 | **Section header table** | one entry, called a **section header**, per **section**: a named piece the linker works with            | `e_shoff`              | `e_shnum` × 64 bytes |
| 3 | **Program header table** | one entry, called a **program header**, per **segment**: a range of the file the loader uses at runtime | `e_phoff`              | `e_phnum` × 56 bytes |
| 4 | **Contents**             | the bytes the two tables describe: code, data, notes, symbols, strings                                  | between the two tables | most of the file     |

The ELF header fields that matter here:

| Field                | Meaning                                                 |
|----------------------|---------------------------------------------------------|
| `e_entry`            | address of the first instruction run                    |
| `e_phoff`, `e_phnum` | where the program header table is, and how many entries |
| `e_shoff`, `e_shnum` | where the section header table is, and how many entries |

Only the ELF header has a fixed position; everything else is found through its offsets.

### Sections and segments

Sections and segments are two ways of dividing the same contents, made for two different moments in the program's life:

- **Sections are for building it.** The assembler and compiler put each kind of content in its own named section: code in `.text`, read-only data in `.rodata`, symbols in `.symtab`, and so on.
- **Segments are for running it.** When the linker produces the executable, it groups the sections by what the loader must do with them, mainly by memory permissions: all read-only sections together, all executable ones together, all writable ones together. Each group becomes a segment.

A segment covers whole sections, with compatible permissions, placed next to each other. For example, `.text` and `aon_text` are in the same executable segment. A section that isn't needed at runtime, such as `.symtab`, is in no segment at all. So every byte the program uses at runtime is in both a section and a segment, while some bytes are only in a section.

|                   | Section: *linking view*                                                                                    | Segment: *execution view*                                                                  |
|-------------------|------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------|
| Described by      | one section header each                                                                                    | one program header each                                                                    |
| Read by           | the linker, debuggers, `readelf`/`objdump`                                                                 | the kernel's ELF loader                                                                    |
| What it is        | a named piece with one purpose: `.text` (code), `.data`, `.symtab` (the symbol table: names for addresses) | a byte range with one set of permissions (`R`, `R E`, `RW`), holding zero or more sections |
| Needed at runtime | no                                                                                                         | yes                                                                                        |

- A **program header** (`Elf64_Phdr`, 56 bytes) describes one **segment**: its type, where its bytes are in the file (`p_offset`, `p_filesz`), where they go in memory (`p_vaddr`) and with which permissions (`p_flags`). The program header table is just the array of all program headers.
- A **section header** (`Elf64_Shdr`, 64 bytes) describes one **section** in the same way, and the section header table is the array of all of them.

### Notes

A **note** is a tagged record that a program carries for tools or the kernel, for example `.note.gnu.build-id`, a unique ID of the build. Each note is:

1. a 12-byte header: `n_namesz` (length of the owner name), `n_descsz` (length of the descriptor), `n_type`;
2. the **owner name**, such as `GNU` or `AoN`;
3. the **descriptor**: the payload, whose format depends on owner and type.

Where notes end up depends on two levels:

- **As sections.** Each note sits in a section of type `SHT_NOTE`, such as `.note.gnu.build-id` or `.note.aon`.
- **As a segment.** If the note section is *allocated* (flag `A`: its bytes must be in memory at runtime), the linker places its bytes inside a `PT_LOAD` segment, so they are mapped into memory with the rest of the program. It also adds a `PT_NOTE` program header that points to the same bytes. (A non-allocated note stays only in the file: it has no `PT_NOTE` entry and is not in memory at runtime.)

### What the loader does

`execve` replaces the process with a new program. For an ELF file, the kernel's ELF loader (`load_elf_binary`) does the work, reading only the ELF header and the program headers (section headers are never consulted):

1. **Picks the load bias.** The binary can indicate that the code is position indipendent, and so it can be placed at random base address. If so a `bias` is randomly picked, otherwise the `bias` is 0.
2. **Maps each `PT_LOAD` segment** at `p_vaddr + bias`, (`p_vaddr` is a field of the program header, `bias` is computed in the step above) with the permissions in `p_flags`.
3. **Records the new image** and **builds the new stack**: updates the process's memory descriptor (`mm`), and passes on the stack the arguments, the environment and the **auxv** (auxiliary vector).
- The **auxv** is a list of key/value pairs that describes the new image to the program. Among them: `AT_PHDR`, the runtime address of the program header table; `AT_PHNUM`, its number of entries; `AT_PHENT`, the size of one entry; `AT_ENTRY`, the entry point. The kernel keeps a copy of the auxv in `mm->saved_auxv`.
4. **Starts the program.** If there is a `PT_INTERP` segment (a dynamically linked program), the loader also maps the named dynamic loader and starts there. Otherwise it starts at the entry point, `e_entry + bias`. A static binary has no `PT_INTERP`.


## 2. The ELF pieces AoN relies on

Of the pieces in section 1, the AoN components use these:

| Piece                                  | View      | What it gives AoN                                                                                            | Used by       |
|----------------------------------------|-----------|--------------------------------------------------------------------------------------------------------------|---------------|
| `PT_LOAD` segments                     | execution | the lowest executable `p_vaddr`, from which the load bias is computed                                        | kernel module |
| `PT_NOTE` segments                     | execution | the allocated notes, `.note.aon` among them, so it is in memory at runtime                                   | kernel module |
| auxv `AT_PHDR`, `AT_PHNUM`, `AT_PHENT` | runtime   | runtime address, count and entry size of the program headers, read from `mm->saved_auxv`                     | kernel module |
| section headers                        | linking   | address, file offset and size of `aon_text`                                                                  | verifier      |
| `.symtab`                              | linking   | `__start_aon_text` / `__stop_aon_text` (generated by ld) and the `__aon_*` ingress gates. Removed by `strip` | verifier      |

## 3. What the note is

`.note.aon` is one note in the format of section 1: owner `AoN`, type `NT_AON_REGION` = 1, and an 8-byte descriptor. `readelf` labels it `NT_VERSION`: it doesn't know the `AoN` owner, so it falls back to a generic meaning of type 1.

```
offset  field     value
0x00    n_namesz  4                         ("AoN\0")
0x04    n_descsz  8                         (two 32-bit values)
0x08    n_type    1                         (NT_AON_REGION)
0x0c    name      "AoN\0"
0x10    desc[0]   __start_aon_text - &desc
0x14    desc[1]   __stop_aon_text  - &desc
```

The descriptor holds two signed 32-bit offsets, each counted **from the descriptor's own address**. So the bounds are:

```
start = &desc + desc[0]
end   = &desc + desc[1]
```

Because the offsets are relative to the note, the loader never has to fix them up. They are correct under any load bias, for `ET_EXEC`, PIE and static-pie alike.

The constants are defined twice and must agree: `AON_NOTE_NAME` / `NT_AON_REGION` in [`kernel/aon.h`](../kernel/aon.h) and the literals in [`aonlibc/aon_syscalls.S`](../aonlibc/aon_syscalls.S).

## 4. How the note is produced

1. **Assembler.** With `-DAON_DEFEND`, `aon_syscalls.S` emits:

   ```asm
   .section .note.aon, "a", @note      # "a" = allocated -> lands in a PT_NOTE
   .long 4, 8, 1                       # namesz, descsz, NT_AON_REGION
   .asciz "AoN"
   1: .long __start_aon_text - 1b      # distance from here: filled in by ld
      .long __stop_aon_text  - 1b
   ```

   Each wrapper (an AoN block plus its `ret`) goes in its own input section. All of these sections are named `aon_text`, kept apart by gas's `unique,N` option, so the linker can keep or drop each one separately.

2. **Linker** (`-Wl,--gc-sections -Wl,-z,start-stop-gc`):
   - `--gc-sections` drops every section nothing references, so the program gets only the wrappers it actually calls.
   - For a section whose name is a valid C identifier, such as `aon_text`, ld generates `__start_<name>` / `__stop_<name>` symbols at its bounds. `-z start-stop-gc` is required: without it, the note's reference to those symbols would count as a use of every `aon_text` section and keep all wrappers.
   - The default linker script doesn't mention `aon_text`, so ld places it as an *orphan* section right after `.text`, in the `R E` segment. It then defines `__start_aon_text` / `__stop_aon_text` and fills in the note's two offsets.
   - `.note.aon` is allocated, so it goes into a `PT_NOTE` segment, possibly next to other notes. ld always keeps note sections, so it survives `--gc-sections`.

3. **Build checks** (in each scenario's Makefile): `verify_aon.py <binary>` (section 6), then `readelf -n | grep AoN`. Either failure fails the build. A missing note also deletes the binary; a verifier failure leaves it on disk.

The baseline build (the undefended control, built without `-DAON_DEFEND`) has the same section layout but no `ud2` and **no note**, so the module never polices it.

## 5. How the kernel module reads it

[`kernel/aon_elf.c`](../kernel/aon_elf.c), `aon_elf_find_region()`.

**When.** The module hooks `finalize_exec`, the last step of `execve`, with a *kprobe*: a callback the kernel runs when a given kernel function is entered. That callback can't sleep, so it only queues a *task_work*: a callback the kernel runs in the process itself, just before it returns to user space. There, `aon_exec_scan()` (in `aon_lifecycle.c`) calls `aon_elf_find_region()`. At that point the new address space is complete, the program hasn't run its first instruction yet, and the code may sleep and load memory pages.

**What it reads.** Only the new address space, never the file: no reopening and no race with the file. A running executable can't be written to (`ETXTBSY`), so the mapped bytes are the file's bytes.

| #  | Step                                                                                                                   | Why                                                                                                                                                                                                         | Produces                                                          |
|----|------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------|
| 1  | `auxv_get(AT_PHDR)`, `auxv_get(AT_PHNUM)`                                                                              | the loader already recorded where the program headers are mapped                                                                                                                                            | `phdr`, `phnum`                                                   |
| 2  | check `AT_PHENT == 56` and `phnum ≤ 4096/56`                                                                           | must be ELF64 headers; the size must be bounded (the loader has the same 4096-byte limit)                                                                                                                   | else `-ENOEXEC`: an ordinary program                              |
| 3  | `kmalloc_array` + `peek()` (`copy_from_user`)                                                                          | the headers are used twice; user memory needs checked access                                                                                                                                                | kernel copy `ph[]`, or `-ENOMEM` / `-EFAULT`                      |
| 4  | `load_bias()`                                                                                                          | `p_vaddr` is a link-time address. The kernel records where the code starts in `mm->start_code` = lowest `p_vaddr` of a `PF_X` `PT_LOAD` + bias. This works even without `PT_PHDR`, which a static-pie lacks | `bias`, or `-ENOEXEC`                                             |
| 5  | for each `PT_NOTE`: `scan_notes(bias + p_vaddr, p_filesz)`                                                             | the note can be in any note segment, next to other owners' notes                                                                                                                                            | first result other than `-ENOENT` wins                            |
| 5a | `peek()` each 12-byte note header; compute `desc_off` and `next`                                                       | step over notes without copying the whole segment                                                                                                                                                           | stop on truncation (`next > size`) or wrap-around (`next <= off`) |
| 5b | filter `n_type == 1 && namesz == 4 && descsz == 8`, then `peek()` the name and descriptor and `memcmp` against `"AoN"` | a type is only meaningful with its owner; other notes cost one header read                                                                                                                                  | `start = addr + desc_off + d[0]`, `end = … + d[1]`                |
| 6  | check `start < end`                                                                                                    | an empty or inverted range is malformed                                                                                                                                                                     | else `-EINVAL`                                                    |
| 7  | `kfree(ph)`                                                                                                            | nothing is kept                                                                                                                                                                                             | `[start, end)` returned to the caller                             |

**What happens next** (`aon_exec_scan()`):

- `0`: `aon_region_add(mm, start, end)` records the region, and the module logs `protecting [start, end)`.
- `-ENOENT` / `-ENOEXEC`: an ordinary program, which is not policed.
- Any other error: a warning is logged and no region is recorded. This fails closed: no thread is ever armed, so the #UD of the binary's first `ud2` is delivered as SIGILL (illegal instruction) and kills it.

A forked child inherits the region, because its address space is a copy of its parent's. The region is dropped when the address space is destroyed (`exit_mmap`).

## 6. How the verifier reads it

[`tools/verify_aon.py`](../tools/verify_aon.py) runs on every defended build. **It does not read the note.** It uses the linking view of the same binary:

1. Check the file starts with `\x7fELF` followed by the ELF64 class byte.
2. Read the section header table (`e_shoff`, `e_shentsize`, `e_shnum`).
3. Read `.symtab` (`SHT_SYMTAB`) and its string table (`sh_link`).
4. Region bounds = the addresses of `__start_aon_text` and `__stop_aon_text`: the same linker symbols the note's offsets were computed from.
5. Ingress gates = the addresses of the `__aon_*` symbols, one per linked block.
6. Region bytes = the section whose `sh_addr`/`sh_size` match the region exactly (`aon_text`), read from the file at its `sh_offset`.
7. Try **every** byte offset, not only instruction starts, for `0f 0b`. Each one must be at an ingress gate; any other one is **stray** → exit 1. A gate without a `ud2` gets a warning.

**Why this check exists.** At a #UD, the module only asks whether the faulting instruction's address (RIP) is inside the AoN region before arming the thread. That shortcut is sound only if the region's only `0f 0b` bytes (the encoding of `ud2`) are the ingress gates. A stray pair, even one hidden inside the bytes of another instruction, would be a second way to arm the thread.

## 7. Kernel vs verifier at a glance

|                      | Kernel module                             | Verifier                               |
|----------------------|-------------------------------------------|----------------------------------------|
| When                 | every exec, at runtime                    | every defended build                   |
| Input                | the process's memory                      | the file                               |
| ELF view             | program headers (`PT_NOTE`)               | section headers + `.symtab`            |
| Source of the bounds | `.note.aon` (offsets from the descriptor) | `__start_/__stop_aon_text` symbols     |
| Needs symbols        | no (works on a stripped binary)           | yes (fails on a stripped binary)       |
| Result               | AoN region recorded for the address space | proof of no stray `ud2` in that region |

Both get their bounds from the same two linker symbols, so they agree by construction. The note is how those bounds survive into the loaded image, where `.symtab` isn't mapped and may be stripped. Nothing currently cross-checks the note's decoded bounds against the symbols.

## 8. Inspecting a real binary

Run from the repository root on x86_64 Linux, with `binutils` (`readelf`, `objdump`, `nm`, `strip`), `python3` and the headers of the running kernel installed.

The commands use `user/cat/cat_defended`, the defended build of the `cat` scenario. Building it already runs the verifier and the note check:

```bash
make -C user/cat cat_defended
cd user/cat
```

**What an ELF is** (section 1): file type and ELF header.

```bash
file cat_defended
readelf -hW cat_defended
```

**The relevant parts** (section 2): segments, the section-to-segment mapping, the sections, and the region symbols.

```bash
readelf -lW cat_defended
readelf -SW cat_defended | grep -E 'note|text|symtab|strtab'
nm cat_defended | grep aon
```

**The note** (section 3): decoded, then as raw bytes with their addresses. The descriptor starts at the note's address + `0x10`; adding each offset to it gives the bounds `nm` prints for `__start_aon_text` and `__stop_aon_text`.

```bash
readelf -nW cat_defended
readelf -x .note.aon cat_defended
```

**The AoN blocks**, the whole `aon_text` section:

```bash
objdump -d -j aon_text cat_defended
```

**The verifier** (section 6), run by hand:

```bash
python3 ../../tools/verify_aon.py cat_defended
```

**The kernel module** (section 5): load it, run the program, read the log. Loading needs root.

```bash
make -C ../../kernel
sudo insmod ../../kernel/aon_mod.ko
./cat_defended aligned; echo "exit=$?"
sudo dmesg | grep 'aon:' | tail -3
```

Expected: a `protecting [start, end)` line with the bounds `nm` printed, then `BLOCKED system call nr=59 ... (unarmed egress gate)`, and `exit=3`.

**Stripped binary** (section 7): the note survives `strip`, so the kernel still protects the binary, but the verifier can't check it (no `.symtab`, exit 2).

```bash
strip -o /tmp/cat_stripped cat_defended
readelf -nW /tmp/cat_stripped | grep AoN
python3 ../../tools/verify_aon.py /tmp/cat_stripped; echo "verify exit=$?"
/tmp/cat_stripped aligned; echo "exit=$?"
```
