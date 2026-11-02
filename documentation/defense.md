# How the AoN defense works

## 0. Background.

An **AoN block** is a system call wrapper that a thread must enter from its first instruction. In this project every wrapper is a **hardened named wrapper**:

```
__aon_read:   ud2                 # ingress gate
              mov  $0, %eax       # body: pins the system call nr (read)
              syscall             # egress gate
              ret                 # outside the block: ordinary return
```

The defense guarantees that a protected process can invoke a system call **only** by running one of these blocks from its ingress gate to its egress gate. It defeats two code-reuse attack vectors:

- **Vector A, aligned gadget**: a jump straight onto the `syscall` of a wrapper, past its ingress gate and body;
- **Vector B, misaligned site**: a jump onto a `0f 05` hidden inside the bytes of an ordinary routine.

The defense has three components, each active in a different phase of the program's life:

| Phase    | Component               | Source                                                                                           | What it does                                                                                                   |
| -------- | ----------------------- | ------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------- |
| 1. build | **hardened library**    | [`aonlibc/nolibc/`](../aonlibc/nolibc/), [`aonlibc/aon_syscalls.S`](../aonlibc/aon_syscalls.S)   | a minimal C library (nolibc) whose wrappers are AoN blocks, gathered in the AoN region and described by a note |
| 1. build | **build-time verifier** | [`tools/verify_aon.py`](../tools/verify_aon.py)                                                  | proves the AoN region has no `ud2` besides the ingress gates                                                   |
| 2. exec  | **kernel module**       | [`kernel/aon_lifecycle.c`](../kernel/aon_lifecycle.c), [`kernel/aon_elf.c`](../kernel/aon_elf.c) | reads the note of the new program and records its AoN region                                                   |
| 3. run   | **kernel module**       | [`kernel/aon_enforce.c`](../kernel/aon_enforce.c), [`kernel/aon_state.c`](../kernel/aon_state.c) | arms the thread at the ingress gate, checks and disarms it at the egress gate, applies the signal rule         |

This guide explains:

- what the build produces (section 1)
- what the kernel module does at exec (2), while the program runs (3), and at fork and exit (4)
- the state the module keeps (5)
- what happens when a hijacked thread tries to reuse a site (6)
- what the defense does not cover (7)

The ELF note itself, and how the module finds it, are explained in detail in [`ELF-note.md`](ELF-note.md).

## 1. Build time

### The base library: nolibc

The hardened library, [`aonlibc/`](../aonlibc/README.md), is built on **nolibc**, the minimal C library that ships with the Linux kernel sources (`tools/include/nolibc`).
- It fits because it is small, header-only and meant for static linking: there is no dynamic loader and almost no startup code, and it issues system calls only through its own `sys_*` raw wrappers, so all of them can be routed through AoN blocks.

nolibc organizes each system call in two layers, both in [`nolibc/sys.h`](../aonlibc/nolibc/sys.h):

- the **public function** (`read()`, `write()`, …): what the program calls. It calls the raw wrapper and translates a negative return into `errno` and `-1` (`__sysret()`);
- the **raw wrapper** (`sys_read()`, `sys_write()`, …): a `static` inline function that issues the `syscall` itself (`my_syscall3(__NR_read, …)`).

For `read`, upstream nolibc boils down to the following (simplified from [`sys.h`](../aonlibc/nolibc/sys.h) and [`arch-x86_64.h`](../aonlibc/nolibc/arch-x86_64.h), with the `my_syscall3()` and `__sysret()` macros expanded):

```c
ssize_t sys_read(int fd, void *buf, size_t count)
{
	register long rax __asm__("rax") = __NR_read;    /* system call nr = 0 (read) */
	register long rdi __asm__("rdi") = fd;           /* 1st argument */
	register long rsi __asm__("rsi") = (long)buf;    /* 2nd argument */
	register long rdx __asm__("rdx") = count;        /* 3rd argument */

	__asm__ volatile ("syscall"                      /* its own syscall: a site in the caller's code */
	                  : "+a"(rax)                    /* rax <- raw kernel value (>= 0, or -errno) */
	                  : "r"(rdi), "r"(rsi), "r"(rdx)
	                  : "rcx", "r11", "memory");     /* syscall clobbers rcx, r11 */
	return rax;
}

ssize_t read(int fd, void *buf, size_t count)
{
	ssize_t ret = sys_read(fd, buf, count);

	if (ret < 0) {                                   /* errno translation */
		errno = -ret;
		return -1;
	}
	return ret;
}
```

### From `read()` to the AoN block

The AoN version replaces only `sys_read`, so every `read` goes through one AoN block.
When compiling with the flag `-DNOLIBC_AON`, `sys.h` declares raw wrappers (`sys_open`, ...) `extern` instead of defining them, so they resolve to the AoN blocks of [`aon_syscalls.S`](../aonlibc/aon_syscalls.S).
The public functions ([`aonlibc/nolibc/sys.h`](../aonlibc/nolibc/sys.h)) are untouched: the program's source does not change, and the `errno` translation stays outside the AoN blocks. 

```c
#ifdef NOLIBC_AON
ssize_t sys_read(int fd, void *buf, size_t count);   /* PoC patch: the AoN block, in aon_syscalls.S */
#else
ssize_t sys_read(int fd, void *buf, size_t count)
{
	return my_syscall3(__NR_read, fd, buf, count);   /* upstream: its own syscall */
}
#endif

ssize_t read(int fd, void *buf, size_t count)
{
	return __sysret(sys_read(fd, buf, count));       /* errno translation, outside the block */
}
```

```asm
	.section	aon_text, "ax", @progbits, unique, 2
sys_read:
__aon_read:
	ud2			/* INGRESS GATE (0f 0b) in defended build */
	movl	$0, %eax	/* body: system call nr = 0 (read)        */
	syscall				/* EGRESS GATE (read)                     */
	ret					/* outside the block: back to the caller  */
```

`ud2` is not present if not compiled with `-DAON_DEFEND`.


**The raw wrapper is the AoN block** ([`aonlibc/aon_syscalls.S`](../aonlibc/aon_syscalls.S)). 
`sys_read` and `__aon_read` are two labels on the same address, so the `call sys_read` lands directly on the ingress gate.

The body needs only one instruction, the one that pins the system call nr, because two calling conventions happen to agree:

| Register          | C function call (System V ABI) | System call (Linux x86_64)            |
| ----------------- | ------------------------------ | ------------------------------------- |
| `rax`             | return value                   | system call nr in, return value out   |
| `rdi`             | 1st argument                   | 1st argument                          |
| `rsi`             | 2nd argument                   | 2nd argument                          |
| `rdx`             | 3rd argument                   | 3rd argument                          |
| `rcx`             | 4th argument (scratch)         | overwritten by `syscall` (return RIP) |
| `r10`             | scratch                        | 4th argument                          |
| `r11`             | scratch                        | overwritten by `syscall` (RFLAGS)     |

- **Arguments.** When `read()` executes `call sys_read`, the compiler has already put `fd`, `buf` and `count` in `rdi`, `rsi` and `rdx`, the same registers where the kernel looks for the arguments of `read`. The block does not touch them.
- **System call nr.** The only thing the kernel needs that C did not provide is the nr in `rax`, which is the body's `movl $0, %eax`. Because the nr is a constant inside the block, the block can only invoke `read`, whatever `rax` held before.
- **Return value.** The kernel leaves its result in `rax`, which is also where C expects a function's return value, so the `ret` after the `syscall` hands it straight to `read()`, which applies `__sysret()`.
- **Clobbered registers.** `syscall` overwrites `rcx` and `r11`. For C these are scratch registers that the caller never expects to survive a call, so nothing needs saving.

The conventions differ only from the 4th argument on (`rcx` for C, `r10` for the kernel). Most wrappers have at most three arguments. `sys_rt_sigaction` has four, so it has a two-instruction stub in `.text`, outside the AoN region, that moves `rcx` to `r10` and jumps to the ingress gate of `__aon_rt_sigaction`.


In a linked defended binary (`objdump -d <program>`), the chain looks like this (addresses are illustrative):

```
00000000004012ac <read>:                      # nolibc public function
  ...
  4012cf:  call   401589 <__aon_read>         #   -> AoN block (== sys_read)
  4012d4:  mov    %rax,-0x8(%rbp)             #   <- the ret lands here
  4012d8:  cmpq   $0x0,-0x8(%rbp)             #   __sysret(): negative -> errno
  ...

0000000000401589 <__aon_read>:                # AoN block, inside aon_text
  401589:  0f 0b             ud2              #   ingress gate: arm
  40158b:  b8 00 00 00 00    mov  $0x0,%eax   #   body: nr = 0 (read)
  401590:  0f 05             syscall          #   egress gate: check and disarm
  401592:  c3                ret              #   outside the block
```

### The defended build

A program is **defended** when it is built against the hardened library with `-DAON_DEFEND`. The build has four steps:

1. **Compile the program** against nolibc with `-DNOLIBC_AON`: the six `sys_*` functions of [`nolibc/sys.h`](../aonlibc/nolibc/sys.h) become `extern`, so every `open()`, `read()`, `write()`, `close()`, `lseek()` and the final `exit()` calls a wrapper of `aon_syscalls.S` instead of issuing its own `syscall`.
2. **Assemble the hardened library** with `-DAON_DEFEND`: each wrapper gains its `ud2` ingress gate, each lives in its own `aon_text` input section (`unique,N`), and the object carries the `.note.aon` section.
3. **Link statically** with `-nostdlib -static -no-pie -Wl,--gc-sections -Wl,-z,start-stop-gc`. The result is one self-contained executable where:
   - **only the required wrappers** are included: `--gc-sections` drops every `aon_text` input section the program never references, and `-z start-stop-gc` stops the note's reference to `__start_aon_text` / `__stop_aon_text` from keeping all of them;
   - **the AoN region is contiguous**: the surviving wrappers are joined into one `aon_text` output section, delimited by `__start_aon_text` and `__stop_aon_text`, and holding nothing but the AoN blocks and their `ret`;
   - **the region is described by the `.note.aon` ELF note**, whose two offsets locate `[__start_aon_text, __stop_aon_text)` relative to the note itself.
   - **every `syscall` of the program is an egress gate**: the C library has no `syscall` of its own, and no dynamic loader or shared library runs.
4. **Verify the AoN region** with `verify_aon.py <program>`, then check with `readelf -n` that the note survived the link. A failed check fails the build.

### The verifier

The kernel module, at the ingress gate, only tests "the `ud2` is inside the AoN region" (section 3). This is sound only if every `0f 0b` in the region is an ingress gate. A stray one, even **misaligned** (hidden inside the bytes of another instruction), would be a second way to arm a thread, from which the attacker could reach any egress gate.

The verifier proves there is none. It reads the executable file (not the note: it uses the section headers and the symbol table, so it must run before `strip`):

1. look up the region bounds, the addresses of `__start_aon_text` and `__stop_aon_text`;
2. collect the ingress gates, the addresses of the `__aon_*` symbols (one per linked block);
3. take the bytes of the `aon_text` section and try **every byte offset**, not only the instruction boundaries, for `0f 0b`;
4. report each `ud2` found: at an ingress gate it is fine, anywhere else it is **stray**, and the verifier exits 1.

It does not check the other static condition of an AoN block, that the body has no explicit control transfer: in the hardened library this holds by construction, since every body is a single `mov`.

## 2. Exec time

The module only acts on programs `exec`'d **after** it is loaded. It hooks the end of `execve` with a kprobe on `finalize_exec()`: the new address space is complete, but the program has not run its first instruction.

1. **Queue the work.** A kprobe handler cannot sleep, and reading user memory may. So `aon_exec_pre()` only queues a task_work (`TWA_RESUME`), which runs in the exec'ing thread on its way back to user space, still before the first user instruction.
2. **Look for the note.** The task_work, `aon_exec_scan()`, calls `aon_elf_find_region()`. It does not read the file: it reads the program headers that the ELF loader already mapped in memory (found through `AT_PHDR` / `AT_PHNUM` in `mm->saved_auxv`) and walks the `PT_NOTE` segments looking for the note with owner `AoN` and type 1 (see [`ELF-note.md`](ELF-note.md), section 4).
3. **Act on the result.**
   - **note found**: its two offsets give the runtime bounds `[start, end)`, which `aon_region_add()` records for this address space (`mm`); the module logs `protecting [start, end)`. From now on the process is **protected**.
   - **no note** (`-ENOENT`), or not an ELF image (`-ENOEXEC`): an ordinary program; nothing is recorded and the module never touches it.
   - **malformed note**, or the region table is full: a warning, and nothing is recorded. This **fails closed**: no thread of the program can be armed, so its first `ud2` raises an ordinary SIGILL and kills it.

The region is recorded per **address space**, not per process: all the threads of a process share it. It is kept in a fixed table of 64 slots keyed by the `mm` pointer (not a hashtable, see section 5).

## 3. Run time

The module watches only the two gates of each block, plus signal delivery. Every hook first tests `aon_region_any()`, a lock-free counter, so when no protected program is running the module costs one atomic read.

### Ingress gate: `ud2` → arm

`ud2` raises #UD, the invalid-opcode fault. The module receives it through a die notifier (`register_die_notifier`, `DIE_TRAP` with `X86_TRAP_UD`). In `aon_die()`:

| Where the `ud2` is                                    | What the module does                                                                                                                                                                                    |
| ----------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| user mode, **inside** the process's AoN region        | **arms** the thread (adds its tid to the armed table), moves RIP past the 2-byte `ud2`, and swallows the fault (`NOTIFY_STOP`): the thread resumes at the first instruction of the body, with no signal |
| **outside** the AoN region, or an unprotected process | nothing (`NOTIFY_DONE`): the kernel handles the #UD as usual and delivers SIGILL                                                                                                                        |

The armed state is **one bit per thread**: arming an armed thread changes nothing.

### Egress gate: `syscall` → check and disarm

Every 64-bit system call is dispatched by `x64_sys_call()`, where the module has a kprobe (`aon_syscall_pre()`). It identifies the `syscall` that entered the kernel by its address: the user RIP saved at entry points after the instruction, so the `syscall` is at `RIP - 2`.

| Where the `syscall` is              | Armed? | Verdict                                                                                          |
| ----------------------------------- | ------ | ------------------------------------------------------------------------------------------------ |
| unprotected process (no AoN region) | —      | allowed, never looked at                                                                         |
| **inside** the AoN region           | yes    | **disarm** and allow: the block ran from its ingress gate to its egress gate                     |
| **inside** the AoN region           | no     | refused: **unarmed egress gate** (vector A, property A2)                                         |
| **outside** the AoN region          | —      | refused: not an egress gate at all (vector B, the vDSO fallback, any stray `0f 05`; property B1) |

Disarming at every allowed egress gate means **one ingress allows exactly one egress**.

A refused system call does not run: by default (`neutralize_mode=1`) the module rewrites the system call nr passed to the dispatcher to an invalid one, so the program sees `-ENOSYS`, and the module logs `BLOCKED system call nr=… at syscall 0x… (reason)`. The thread keeps running, and the program decides what to do with the error.

### Signal rule: disarm before a handler

A signal can interrupt an armed thread between its ingress and its egress gate. If the thread stayed armed, the handler (or a forged signal frame) could reach an egress gate it never entered. So, with a kprobe on `x64_setup_rt_frame()`, called only when the kernel is about to run a user handler, the module **disarms** the thread before the handler runs; `rt_sigreturn` never re-arms it.

The cost: when the handler returns, the interrupted block's egress gate is unarmed and is refused, so the caller must execute the block again. In exchange, a handler can never reuse an egress gate, whether the thread it interrupted was armed or not.

## 4. Fork and exit

The region and the armed state must follow the life of the address space and of the thread, so that a new process is protected as its parent was and a recycled pointer or tid never inherits stale state.

| Event                                                                           | Hook (kprobe)        | What the module does                                                                                                                                                              |
| ------------------------------------------------------------------------------- | -------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **fork**: a child with its own `mm`                                             | `wake_up_new_task()` | copies the parent's region to the child's `mm` (`aon_region_copy()`): the child's address space is a copy, so the same addresses apply. Runs before the child's first instruction |
| **thread** or **vfork** (`CLONE_VM`)                                            | `wake_up_new_task()` | nothing: the child shares the parent's `mm`, hence its region                                                                                                                     |
| **exec**                                                                        | `finalize_exec()`    | the new image decides (section 2); the old `mm` is torn down, which drops its region (next row)                                                                                   |
| **address space destroyed** (process exit, or the old `mm` replaced by an exec) | `exit_mmap()`        | frees the region's slot (`aon_region_del()`), before the `mm` can be freed and its pointer reused                                                                                 |
| **thread exit**                                                                 | `do_exit()`          | removes the thread's armed entry, if any, so a recycled tid never starts armed                                                                                                    |
| **module unload**                                                               | `aon_exit()`         | unregisters every hook and frees all the armed entries                                                                                                                            |

The armed state is never inherited: it is keyed by tid, and a new thread has a new tid.

## 5. The state the module keeps

All of it is in [`kernel/aon_state.c`](../kernel/aon_state.c). The hooks run in probe or exception context, where they cannot sleep, so both tables are protected by spinlocks taken with `irqsave` and allocate with `GFP_ATOMIC`.

|               | AoN regions                                                               | Armed state                                                                                          |
| ------------- | ------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| Granularity   | one per address space (`mm`)                                              | one bit per thread (tid)                                                                             |
| Structure     | fixed array of 64 slots `{mm, start, end}`, linear scan                   | hashtable with 1024 buckets (`DEFINE_HASHTABLE(armed_ht, 10)`); a thread is armed if it has an entry |
| Filled at     | exec (note found), fork (copy)                                            | ingress gate (`kmalloc` of one entry)                                                                |
| Read at       | ingress gate, egress gate                                                 | egress gate, signal delivery                                                                         |
| Released at   | `exit_mmap()` (slot marked free)                                          | egress gate, signal delivery, `do_exit()` (`kfree` of the entry), module unload                      |
| When it fails | table full: the region is not recorded, the program fails closed (SIGILL) | `kmalloc` fails: the thread is not armed, its egress gate is refused                                 |

Both failure modes fail closed: they can make a protected program fail, never let a system call through.

## 6. Example: a hijacked thread

Take a protected program whose AoN region holds only the blocks of its required system calls, `execve` not among them. An attacker hijacks a thread: they control its registers and where it jumps next, and want it to invoke `execve` (nr 59), so they set `eax = 59` and the arguments, then jump to a site. Every choice of site fails:

| Jump target                                                              | What the module sees                                                       | Outcome                                                                     |
| ------------------------------------------------------------------------ | -------------------------------------------------------------------------- | --------------------------------------------------------------------------- |
| the `syscall` of `__aon_read` (**vector A**, aligned gadget)              | a `syscall` inside the AoN region, thread not armed (it skipped the `ud2`) | refused: unarmed egress gate                                                |
| a `0f 05` hidden inside an ordinary routine in `.text` (**vector B**, misaligned site) | a `syscall` outside the AoN region                                         | refused: outside the AoN region                                             |
| the `ud2` of `__aon_read` (whole-block reuse)                             | an ingress gate, then its egress gate                                      | allowed, but the body overwrites `eax` with 0: the kernel runs `read`, not `execve` |
| a `ud2` the attacker finds elsewhere in the region                        | —                                                                          | cannot exist: the verifier proved every `0f 0b` in the region is an ingress gate |

The two refusals show up in the kernel log as:

```
aon: pid=… comm=…: protecting [start, end)                                       # at exec
aon: BLOCKED system call nr=59 at syscall 0x… (unarmed egress gate) (pid=… comm=…)    # vector A
aon: BLOCKED system call nr=59 at syscall 0x… (outside the AoN region) (pid=… comm=…) # vector B
```

In both cases `execve` never runs: the thread gets `-ENOSYS` and continues. An unprotected program (built without `-DAON_DEFEND`, so with no note) is never policed, and the same jumps succeed even with the module loaded.

## 7. What the defense does not cover

- **Whole-wrapper reuse.** The body pins the system call nr but does not validate the arguments (by design). An attacker who jumps to an ingress gate runs a legitimate block with arguments of their choice. What is gone is the ability to invoke a system call the program never required: a program that never calls `execve` has no `execve` block at all.
- **Other kernel entry paths.** Only `x64_sys_call()` is observed. The compat entries (`int $0x80`, `sysenter`, a `syscall` with `__X32_SYSCALL_BIT`) bypass it, and so do the ia32/x32 signal frames.
- **AoN region immutability.** The module trusts that the bytes of the region stay those verified at build time; it does not stop the program from remapping or rewriting them (e.g. `mprotect` + write), although doing so requires system calls that must themselves pass an egress gate.
- **Programs exec'd before the module was loaded** are not protected, and **dynamic executables** cannot be: their loader and shared libraries issue system calls outside the executable's AoN region.
