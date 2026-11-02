# The AoN ELF note

## 0. Background.

An **AoN block** is a system call wrapper that a thread must enter from its first instruction: `ud2 ; mov $nr,%eax ; syscall`. A kernel module, `aon_mod`, enforces this:

- `ud2` is the **ingress gate**. It raises #UD, the invalid-opcode fault. The module catches the fault, **arms** the thread (records that it entered a block) and resumes it after the `ud2`.
- `syscall` is the **egress gate**. The module lets the system call through only if the thread is armed, then disarms it.

The **AoN region** is the address range holding all the linked AoN blocks. The linker puts them in one *section* (a named piece of the executable, see section 1), `aon_text`, and marks its bounds with two *symbols* (names for addresses), `__start_aon_text` and `__stop_aon_text`. A `syscall` outside this range is refused.

So the module must know each program's AoN region. The program carries it in an **ELF note**, a small tagged record inside the executable, named `.note.aon`. A program built with the AoN blocks and the note is a **defended** build.

This guide explains:

- the parts of ELF involved (sections 1–2)
- the note (3) and how it is produced (4)
- how the kernel module finds the region at runtime (5)

## 1. What an ELF is

ELF (*Executable and Linkable Format*) is the file format Linux uses for object files, executables and shared libraries.

### Layout

An ELF file has four parts:

| #   | Part                     | What it holds                                                                                           | Starts at              | Size                 |
| --- | ------------------------ | ------------------------------------------------------------------------------------------------------- | ---------------------- | -------------------- |
| 1   | **ELF header**           | identity of the file and where the two tables are (see below)                                           | always `0`             | 64 bytes             |
| 2   | **Section header table** | one entry, called a **section header**, per **section**: a named piece the linker works with            | `e_shoff`              | `e_shnum` × 64 bytes |
| 3   | **Program header table** | one entry, called a **program header**, per **segment**: a range of the file the loader uses at runtime | `e_phoff`              | `e_phnum` × 56 bytes |
| 4   | **Contents**             | the bytes the two tables describe: code, data, notes, symbols, strings                                  | between the two tables | most of the file     |

The ELF header fields that matter here:

| Field                | Meaning                                                 |
| -------------------- | ------------------------------------------------------- |
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
| ----------------- | ---------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
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

### Static and dynamic executables

An executable needs library code (for example the C library) as well as its own. ELF allows two ways to provide it:

- **Static.** At link time, the linker copies the library code the program uses into the executable. The file is self-contained: the kernel maps it and jumps straight to its entry point.
- **Dynamic.** The library code stays in separate shared libraries (`.so` files). The executable names a *dynamic loader* (`ld-linux-x86-64.so.2`) in a `PT_INTERP` segment. At startup, the dynamic loader maps the shared libraries and connects the program's calls to them. The program's code and the libraries' code then live in different files and memory ranges.

**This project uses static executables.** Each scenario is linked with `-nostdlib -static` against a minimal C library and the AoN wrappers, so every system call the program makes goes through an AoN block inside the executable itself. This is what lets one note, in the executable, describe the whole AoN region.
A dynamic program would not fit: the dynamic loader and the shared C library issue system calls from their own code, outside the executable's AoN region, and the module would refuse them.

### What the loader does

`execve` replaces the process with a new program. For an ELF file, the kernel's ELF loader (`load_elf_binary`) does the work, reading only the ELF header and the program headers (section headers are never consulted):

1. **Picks the load bias.** The binary can indicate that the code is position independent, so it can be placed at a random base address. If so a `bias` is randomly picked, otherwise the `bias` is 0.
2. **Maps each `PT_LOAD` segment** at `p_vaddr + bias`, (`p_vaddr` is a field of the program header, `bias` is computed in the step above) with the permissions in `p_flags`.
3. **Records the new image** and **builds the new stack**: updates the process's memory descriptor (`mm`), and passes on the stack the arguments, the environment and the **auxv** (auxiliary vector).
   - The **auxv** is a list of key/value pairs that describes the new image to the program. Among them: `AT_PHDR`, the runtime address of the program header table; `AT_PHNUM`, its number of entries; `AT_PHENT`, the size of one entry; `AT_ENTRY`, the entry point. The kernel keeps a copy of the auxv in `mm->saved_auxv`.
4. **Starts the program.** For a static binary, it starts at the entry point, `e_entry + bias`.


## 2. The ELF pieces AoN relies on

Of the pieces in section 1, the kernel module uses these:

| Piece                                  | View      | What it gives the kernel module                                                          |
| -------------------------------------- | --------- | ---------------------------------------------------------------------------------------- |
| `PT_LOAD` segments                     | execution | the lowest executable `p_vaddr`, from which the load bias is computed                    |
| `PT_NOTE` segments                     | execution | the allocated notes, `.note.aon` among them, so it is in memory at runtime               |
| auxv `AT_PHDR`, `AT_PHNUM`, `AT_PHENT` | runtime   | runtime address, count and entry size of the program headers, read from `mm->saved_auxv` |

Section headers and symbols are not used: the kernel never reads them, and `strip` may remove the symbols.

## 3. What the note is

The AoN region corresponds to the `aon_text` section, which is delimited by two symbols `__start_aon_text` and `__stop_aon_text`: 

```
__start_aon_text:
__aon_open:   ud2                 # ingress gate
              mov  $2, %eax       # system call nr (open)
              syscall             # egress gate
              ret
__aon_read:   ud2
              mov  $0, %eax       # read
              syscall
              ret
              …                   # one block per required system call
__aon_exit:   ud2
              mov  $60, %eax      # exit
              syscall
              ret
__stop_aon_text:                  # first byte after the last block
```

The information is stored in the ELF as a note, `.note.aon`: owner `AoN`, type = 1, and an 8-byte (2 32-bit values) descriptor.

```
offset  field     value
0x00    n_namesz  4                         ("AoN\0")
0x04    n_descsz  8                         (two 32-bit values)
0x08    n_type    1                         
0x0c    name      "AoN\0"
0x10    desc[0]   offset of __start_aon_text relative to here
0x14    desc[1]   offset of __stop_aon_text  relative to here
```

The descriptor holds two signed 32-bit offsets, each counted from the descriptor's own address. So the real bounds of the AoN region are:

```
start of the AoN region = __start_aon_text = &desc + desc[0]
end   of the AoN region = __stop_aon_text  = &desc + desc[1]
```

Because the offsets are relative to the note, they are correct under any load bias.

## 4. How the note is produced

The note comes out of the normal build of a defended program (using the `-DAON_DEFEND` flag), which has two steps:

- **Assemble and compile.** `gcc -DAON_DEFEND -c aon_syscalls.S -o aon_syscalls.aon.o` runs the C preprocessor. The result is an object file holding the wrappers and the `.note.aon` section. The note's two offsets are still blank, because the final addresses aren't known yet.
- **Link.** `gcc … -o cat_defended cat.o aon_syscalls.aon.o …` runs the linker (ld). It keeps only the wrappers the program calls, joins them into one `aon_text` section, defines `__start_aon_text` / `__stop_aon_text`, fills in the note's offsets and groups all the sections into segments.

The two parts below follow what ends up in the binary: first the **region** that the wrappers form, then the **note** that describes it.

1. **The region (`aon_text`).**

    The library object, `aon_syscalls.aon.o`, contains one `aon_text` *input* section per wrapper. They all have the same name, kept apart by `unique,N` option, so the linker can keep or drop each one separately:

    ```asm
    .section aon_text, "ax", @progbits, unique, 1     # input section no. 1
    __aon_open:
        ud2                       # ingress gate
        movl  $2, %eax            # system call nr (open)
        syscall                   # egress gate
        ret

    .section aon_text, "ax", @progbits, unique, 2     # input section no. 2
    __aon_read:
        …
    ```

    The fields of `.section aon_text, "ax", @progbits, unique, 1`:

    - `aon_text`: the section name. All wrappers share it, so the linker can join them into one output section.
    - `"ax"`: the flags. `a` = allocated (in memory at runtime), `x` = executable, so the section lands in the `R E` segment next to `.text`.
    - `@progbits`: the section type, `SHT_PROGBITS`: code or data whose bytes are stored in the file.
    - `unique, 1`: an ID that makes this a separate section from the other `aon_text` sections, so each wrapper can be kept or dropped on its own.

    The linker keeps the ones the program calls and joins them into a single `aon_text` *output* section:

    ```
    aon_syscalls.aon.o (input)                cat_defended (output)

    aon_text: (unique 1)                      aon_text:
        __aon_open               kept             __start_aon_text
    aon_text: (unique 2)                        __aon_open
        __aon_read               kept             __aon_read
    aon_text: (unique 3)                        __aon_close
        __aon_close              kept             __aon_write
    aon_text: (unique 4)                        __aon_exit
        __aon_write              kept             __stop_aon_text
    aon_text: (unique 5)
        __aon_exit               kept
    aon_text: (unique 9)
        __aon_lseek              dropped
    aon_text: (unique 6)
        __aon_rt_sigaction       dropped
    …                          
    ```

    The defended program is linked with:

    ```
    gcc … -Wl,--gc-sections -Wl,-z,start-stop-gc -o cat_defended cat.o aon_syscalls.aon.o …
    ```

    - `-Wl,--gc-sections` drops every section nothing references, so the program gets only the wrappers it actually calls.
    - For a section whose name is a valid C identifier, such as `aon_text`, ld generates `__start_<name>` / `__stop_<name>` symbols at its bounds.
      - `-Wl,-z start-stop-gc` is required: without it, the note's reference to those symbols would count as a use of every `aon_text` section and keep all wrappers.

2. **The note (`.note.aon`).** When built with the defense (`-DAON_DEFEND`), `aon_syscalls.S` also emits the note:

   ```asm
   .section .note.aon, "a", @note      # "a" = allocated -> lands in a PT_NOTE
   .long 4, 8, 1                       # namesz, descsz, type
   .asciz "AoN"
   1: .long __start_aon_text - 1b      # distance from here: filled in by ld
      .long __stop_aon_text  - 1b
   ```

## 5. How the kernel module reads it

The module looks for the region once per `execve`, in `aon_elf_find_region()` ([`kernel/aon_elf.c`](../kernel/aon_elf.c)). It reads only the new program's memory, never the file. The steps:

1. **Wait until the new program is in memory.** The module hooks `finalize_exec`, the last step of `execve`, with a *kprobe*. A kprobe callback cannot sleep, and reading user memory may sleep, so it queues a *task_work*: a callback the kernel runs in the process itself, just before it returns to user space. That callback, `aon_exec_scan()` ([`kernel/aon_lifecycle.c`](../kernel/aon_lifecycle.c)), calls `aon_elf_find_region()`. At this point the new address space is complete and the program has not run its first instruction yet.

2. **Find the program headers.** The ELF loader already mapped the program header table and recorded it in the auxv (section 1). The module reads two entries from `mm->saved_auxv`:
   - `AT_PHDR`: the runtime address of the table;
   - `AT_PHNUM`: its number of entries.

3. **Check that they make sense.** `AT_PHENT` must be 56, the size of an ELF64 program header, and the table must fit in 4096 bytes (at most 73 entries), the same limit the loader applies. Otherwise the result is `-ENOEXEC`, and the program is treated as an ordinary one.

4. **Copy the program headers into the kernel.** The table is in user memory, which kernel code must not read directly. The module allocates a kernel buffer (`kmalloc_array`) and copies the table into it with `peek()`, a wrapper around `copy_from_user`.
   - That function checks that the address belongs to the program, loads the page from disk if needed (this is the part that may sleep), and fails with `-EFAULT` instead of crashing if the address is not mapped. The table is copied once, because the next two steps both read it.

5. **Compute the load bias.**
   - **Why it is needed.** The next step must read the `PT_NOTE` segments in memory. A program header gives only `p_vaddr`, the address the *linker* chose. The loader placed every segment at `p_vaddr + bias` (section 1), so the module needs `bias` to turn `p_vaddr` into the address where the note really is.
   - **Why it must be recomputed.** The loader does not store the bias anywhere the module can read. The usual trick, used by user-space loaders, is `bias = AT_PHDR - p_vaddr of the PT_PHDR segment` (the same table, at runtime and at link time). But a static executable may have no `PT_PHDR` segment at all.
   - **How it is recomputed.** The loader, while mapping the segments, remembers the lowest `p_vaddr` among the executable `PT_LOAD` segments, then adds the bias, and at the end saves the result as `mm->start_code` (the start of the program's code). So the module can scan its copy of the program headers and find the same lowest `p_vaddr` and subtracts it:

     ```
     mm->start_code = lowest executable p_vaddr + bias             (stored by the loader)
     bias           = mm->start_code - lowest executable p_vaddr   (computed by the module)
     ```

   - **Example.** In `cat_defended` the only executable `PT_LOAD` has `p_vaddr = 0x401000`. It is not position independent, so the loader uses bias 0, `mm->start_code` is `0x401000`, and the module computes `bias = 0x401000 - 0x401000 = 0`. If the same program were a static-pie linked at `p_vaddr = 0x1000` and the loader picked bias `0x7f0000000000`, `mm->start_code` would be `0x7f0000001000`, and the subtraction would give back `0x7f0000000000`.

6. **Walk every note in every `PT_NOTE` segment.** A note segment starts at runtime address `bias + p_vaddr` and is `p_filesz` bytes long, and the AoN note may sit in any of them, next to other owners' notes. For each note, in order:
   1. Copy its 12-byte header and compute where its name, its descriptor and the next note start (each part is padded to the segment's alignment, 4 or 8 bytes). If the note would end past the segment, or the offsets wrap around, stop walking this segment.
   2. Skip the note unless `n_type == 1`, `n_namesz == 4` and `n_descsz == 8`. Notes of other owners cost one header read.
   3. Copy the name and the descriptor. If the name is `"AoN"`, compute the bounds as in section 3: `start = &desc + desc[0]`, `end = &desc + desc[1]`.

   The first AoN note found wins. If no segment has one, the result is `-ENOENT`: an ordinary program.

7. **Check the range.** `start` must be lower than `end`; an empty or inverted range is malformed, and the result is `-EINVAL`.

8. **Free the copy and return.** The program header copy is freed (`kfree`): the module keeps nothing but `[start, end)`.

9. **Act on the result** (in `aon_exec_scan()`):
   - success: `aon_region_add(mm, start, end)` records the region for this address space, and the module logs `protecting [start, end)`;
   - `-ENOENT` or `-ENOEXEC`: an ordinary program, which is not policed;
   - any other error: a warning is logged and no region is recorded. This fails closed: no thread is ever armed, so the #UD of the program's first `ud2` is delivered as SIGILL (illegal instruction) and kills it.

The region then follows the address space: a forked child gets a copy of it, threads share it, and it is dropped when the address space is destroyed (`exit_mmap`).
