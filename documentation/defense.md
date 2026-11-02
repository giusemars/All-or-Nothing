# How the AoN defense works

## Background

An **AoN block** is a system call wrapper that a thread can only run from its first instruction. In this project every wrapper is a **hardened named wrapper**:

```
__aon_read:   ud2                 # ingress gate
              mov  $0, %eax       # body: pins the system call nr (read)
              syscall             # egress gate
              ret                 # outside the block: ordinary return
```

With the defense, a protected process can invoke a system call **only** by running one of these blocks from start to end: from its ingress gate to its egress gate.

The defense has three parts. Each one works at a different moment in the program's life:

| When             | Part                    | Source                                                                                           | What it does                                                                                               |
| ---------------- | ----------------------- | ------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------- |
| Build            | **hardened library**    | [`aonlibc/nolibc/`](../aonlibc/nolibc/), [`aonlibc/aon_syscalls.S`](../aonlibc/aon_syscalls.S)   | a small C library whose wrappers are AoN blocks, all in one region, described by a note                    |
| Build            | **build-time verifier** | [`tools/verify_aon.py`](../tools/verify_aon.py)                                                  | checks that the AoN region has no `ud2` except the ingress gates                                           |
| Startup/teardown | **kernel module**       | [`kernel/aon_lifecycle.c`](../kernel/aon_lifecycle.c), [`kernel/aon_elf.c`](../kernel/aon_elf.c) | reads the note of the new program, saves where its AoN region is, copies it at fork and removes it at exit |
| Run              | **kernel module**       | [`kernel/aon_enforce.c`](../kernel/aon_enforce.c), [`kernel/aon_state.c`](../kernel/aon_state.c) | arms the thread at the ingress gate, checks and disarms it at the egress gate                              |

<!-- This guide explains:

- what the build produces
- what the kernel module does when a program starts and ends, and while it runs
- what data the module keeps
- what happens when an attacker takes control of a thread
- what the defense does not cover

The ELF note, and how the module finds it, are explained in [`ELF-note.md`](ELF-note.md). -->

## Build time

**Goal:** build the program so that it invokes system calls only through AoN blocks, with only the blocks it needs, all in one AoN region that an ELF note describes, and with no `ud2` in that region except the ingress gates.

### The base library: nolibc

The hardened library, [`aonlibc/`](../aonlibc/README.md), is built on **nolibc**, the small C library that comes with the Linux kernel sources (`tools/include/nolibc`).
- It is a good fit because it is small, made only of headers, and meant to be linked statically: there is no dynamic loader, almost no startup code, and every system call goes through one of its `sys_*` raw wrappers. So all of them can be replaced by AoN blocks.

In nolibc each system call has two layers, both in [`nolibc/sys.h`](../aonlibc/nolibc/sys.h):

- the **public function** (`read()`, `write()`, …): what the program calls. It calls the raw wrapper and, if the result is negative, sets `errno` and returns `-1` (`__sysret()`);
- the **raw wrapper** (`sys_read()`, `sys_write()`, …): a small `static` function that runs the `syscall` itself (`my_syscall3(__NR_read, …)`).

For `read`, the original nolibc code is roughly this (simplified from [`sys.h`](../aonlibc/nolibc/sys.h) and [`arch-x86_64.h`](../aonlibc/nolibc/arch-x86_64.h), with the `my_syscall3()` and `__sysret()` macros written out):

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

### Hardened wrapper

The AoN version replaces only `sys_read`, so every `read` goes through the same AoN block.
With the flag `-DNOLIBC_AON`, `sys.h` only declares the raw wrappers as `extern`, without a body. The linker then connects them to the AoN blocks in [`aon_syscalls.S`](../aonlibc/aon_syscalls.S).
The public functions in [`aonlibc/nolibc/sys.h`](../aonlibc/nolibc/sys.h) do not change: the program's source stays the same, and the `errno` handling stays outside the AoN blocks.

```c
#ifdef NOLIBC_AON
extern ssize_t sys_read(int fd, void *buf, size_t count);   /* PoC patch: the AoN block, in aon_syscalls.S */
#else
ssize_t sys_read(int fd, void *buf, size_t count)
{
	register long rax __asm__("rax") = __NR_read;    /* system call nr = 0 (read) */
	...
	return rax;
}
#endif

ssize_t read(int fd, void *buf, size_t count)
{
	return __sysret(sys_read(fd, buf, count));       /* errno translation, outside the block */
}
```

In the AoN version, the wrappers are hardened with AoN blocks. They are in [`aonlibc/aon_syscalls.S`](../aonlibc/aon_syscalls.S), and they are roughly like this:

```asm
	.section	aon_text, "ax", @progbits, unique, 2
sys_read:
__aon_read:
	ud2			        /* INGRESS GATE (0f 0b) in defended build */
	movl	$0, %eax	/* body: system call nr = 0 (read)        */
	syscall				/* EGRESS GATE (read)                     */
	ret					/* outside the block: back to the caller  */
```

- `ud2` is only there when the file is built with `-DAON_DEFEND`.
- `sys_read` and `__aon_read` are two names for the same address, so `call sys_read` jumps straight to the ingress gate.
- The body only sets the system call nr, because C calls and Linux system calls use the same registers for the first three arguments (`rdi`, `rsi`, `rdx`) and for the return value (`rax`). The 4th argument differs (`rcx` for C, `r10` for the kernel), so a wrapper with four or more arguments has a small stub outside the AoN region that copies `rcx` to `r10` before jumping to its ingress gate.

### AoN region

All the AoN blocks of a program are placed next to each other in one continuous range of memory, the **AoN region**:

```
__start_aon_text:
__aon_open:   ud2 ; mov $2, %eax ; syscall ; ret
__aon_read:   ud2 ; mov $0, %eax ; syscall ; ret
              …                    # one block per required system call
__stop_aon_text:                   # first byte after the last block
```

- **One section.** Every block is in a section named `aon_text`. The linker joins them into a single `aon_text` section and marks its start and end with two symbols, `__start_aon_text` and `__stop_aon_text`. So the region is `[__start_aon_text, __stop_aon_text)`.
- **Only the required blocks.** Each block starts in its own small `aon_text` section, so the linker can keep or drop it on its own. With `--gc-sections` it keeps only the blocks the program calls, and `-z start-stop-gc` stops the two symbols from keeping all of them. A program that never calls `execve` has no `execve` block.
- **Nothing else inside.** The region holds only the AoN blocks and the `ret` after each one. So the kernel can treat "inside the region" as "inside an AoN block": a `syscall` outside the region is never an egress gate.
- **Described by a note.** The kernel does not read symbols. The program tells it where the region is through the `.note.aon` ELF note, which stores the two limits as offsets from the note itself, so they stay right wherever the program is loaded.

[`ELF-note.md`](ELF-note.md) explains the note in detail: its format ("What the note is"), how the linker builds the region and fills in the note ("How the note is produced"), and how the kernel module finds it at exec ("How the kernel module reads it").

### Static linking

A defended program is linked **statically**: `-nostdlib` leaves out the system C library (glibc) and its startup code, and `-static` copies all the code the program uses into the executable. Nothing else is loaded at run time.

This matters because the module refuses every `syscall` outside the AoN region, and there is one region per program, described by the note in the executable:

- **One file holds every `syscall`.** With static linking, all the code that can invoke a system call (the program and nolibc) is in the executable, so all of it can go through the AoN blocks of its one region.
- **No dynamic loader.** A dynamic program starts in the loader (`ld-linux-x86-64.so.2`), which maps the shared libraries with its own `syscall`s, before the program runs. Those `syscall`s are outside the executable's AoN region and would be refused.
- **No shared libraries.** A shared C library (`libc.so`) has its own `syscall` instructions, in its own memory range, outside the region. It would also bring in every wrapper it contains, not only the ones the program needs.
- **No vDSO.** The kernel maps the vDSO into every process, and it contains a fallback `syscall`. nolibc does not use the vDSO, so that `syscall` is never reached; if it were, it would be refused as outside the region.

The project also links with `-no-pie`, so the program is loaded at a fixed address. The defense does not depend on it: the note stores the region's limits relative to itself, and the module computes the load address at exec. See [`ELF-note.md`](ELF-note.md), "Static and dynamic executables".

### The verifier

At an ingress gate, the kernel module only checks that the `ud2` is inside the AoN region (see [Run time](#run-time)).
This is only safe if every `0f 0b` in the region is an ingress gate. Even a **misaligned** one hidden inside the bytes of another instruction, would give an attacker another way to arm a thread.

The verifier makes sure there is no such extra `ud2`. It reads the executable file. It does not use the note: it uses the section headers and the symbol table. It:

1. finds the region's limits, the addresses of `__start_aon_text` and `__stop_aon_text`;
2. finds the ingress gates, the addresses of the `__aon_*` symbols (one per block);
3. looks for `0f 0b` at **every byte** of the `aon_text` section, not only where instructions start;
4. reports each `ud2` it finds: at an ingress gate it is fine, anywhere else it is **stray**, and the verifier exits with 1.

### The defended build

This sums up the build time phase. A program is **defended** when it is built in four steps:

1. **compile** the program against nolibc with `-DNOLIBC_AON`, which decides **where** the raw wrappers come from: every public function calls an AoN block of `aon_syscalls.S` instead of running its own `syscall`;
2. **assemble** the hardened library with `-DAON_DEFEND`, which decides **whether** those wrappers are hardened: each one gets its `ud2` ingress gate and sits in its own `aon_text` section, and the `.note.aon` note is added. Both flags are needed: without the first the blocks are never called, without the second they have no ingress gates and no note;
3. **link** statically with `-nostdlib -static -Wl,--gc-sections -Wl,-z,start-stop-gc` (see [Static linking](#static-linking));
4. **verify** the result with `verify_aon.py`, and check with `readelf -n` that the note is still there. If a check fails, the build fails.

The result is one self-contained executable where:

- **only the required wrappers** are included: the linker drops every AoN block the program never calls;
- **all the AoN blocks are in one continuous region**, `[__start_aon_text, __stop_aon_text)`, with nothing else in it but their `ret`;
- **the `.note.aon` ELF note says where the region is**, relative to the note itself, so the kernel can find it at exec time;
- **every `syscall` in the program is an egress gate**: the C library has no `syscall` of its own, and there is no dynamic loader or shared library;
- **every `ud2` in the region is an ingress gate**, as the verifier checked.

## Startup and teardown time

**Goal:** when a program starts, the kernel module must read its `.note.aon` ELF note, if it has one, and save where the AoN region is for the program's address space. The run-time checks then use this saved region. The saved state must then follow the process: a forked child is protected like its parent, and when an address space or a thread goes away its state is removed, so a reused `mm` pointer or tid never picks up old state.

The module only protects programs started (with `execve`) **after** the module was loaded.

| Event                               | Hook                     | Symbol               | Handler               | Source                                                |
| ----------------------------------- | ------------------------ | -------------------- | --------------------- | ----------------------------------------------------- |
| exec                                | kprobe                   | `finalize_exec()`    | `aon_exec_pre()`      | [`kernel/aon_lifecycle.c`](../kernel/aon_lifecycle.c) |
| exec (before the first instruction) | task_work (`TWA_RESUME`) | —                    | `aon_exec_scan()`     | [`kernel/aon_lifecycle.c`](../kernel/aon_lifecycle.c) |
| fork, clone                         | kprobe                   | `wake_up_new_task()` | `aon_fork_pre()`      | [`kernel/aon_lifecycle.c`](../kernel/aon_lifecycle.c) |
| address space destroyed             | kprobe                   | `exit_mmap()`        | `aon_exit_mmap_pre()` | [`kernel/aon_lifecycle.c`](../kernel/aon_lifecycle.c) |
| thread exit                         | kprobe                   | `do_exit()`          | `aon_do_exit_pre()`   | [`kernel/aon_lifecycle.c`](../kernel/aon_lifecycle.c) |

### Exec: read the note

The kprobe on `finalize_exec()` fires when the new program is fully loaded in memory but has not run any instruction yet.

1. **Schedule the work.** A kprobe cannot wait, and the module needs to read the program's memory to read the ELF note.
   -  So the kprobe handler `aon_exec_pre()` only schedules a task_work (`TWA_RESUME`) `aon_exec_scan()`: a function that the kernel runs for this thread just before it returns to the program, still before its first instruction.
2. **Look for the note.** The `aon_exec_scan()` function, calls `aon_elf_find_region()`.
   - It does not read the file on disk. It reads the program headers the ELF loader already put in memory (found through `AT_PHDR` / `AT_PHNUM` in `mm->saved_auxv`) and goes through the `PT_NOTE` segments, looking for the note with owner `AoN` and type 1 (see [`ELF-note.md`](ELF-note.md), "How the kernel module reads it").
3. **Use the result.**
   - **note found**: it gives the region's runtime limits `[start, end)`. `aon_region_add()` saves them for this address space (`mm`) and the module logs `protecting [start, end)`. The process is now **protected**.
     - The region is saved per **address space** (`mm`), not per process, so all the threads of a process share it. It is kept in a fixed table of 64 slots, one per `mm` (not a hashtable, see [The state the module keeps](#the-state-the-module-keeps)).
   - **no note** (`-ENOENT`), or not an ELF file (`-ENOEXEC`): an ordinary program. Nothing is saved and the module ignores it.
   - **broken note**, or no free slot in the region table: the module logs a warning and saves nothing. The program is then blocked, not left unprotected: no thread can be armed, so its first `ud2` causes a normal SIGILL and the program is killed.

### Fork: copy the region

`aon_fork_pre()` runs once the child is created, before it runs its first instruction.

- **fork** (the child has its own `mm`): the module copies the parent's region to the child's `mm` (`aon_region_copy()`). The child's memory is a copy of the parent's, so the addresses are the same.
- **thread** or **vfork** (`CLONE_VM`): nothing to do, the child shares the parent's `mm`, and so its region.

The armed state is never inherited: it is stored by tid, and a new thread has a new tid.

### Exit: remove the state

- **address space destroyed** (the process exits, or an exec replaces the old `mm`): `aon_exit_mmap_pre()` frees the region's slot (`aon_region_del()`) before the `mm` is freed and its pointer can be reused.
- **thread exit**: `aon_do_exit_pre()` removes the thread's armed entry, if there is one, so a reused tid never starts armed.
- **module unload**: `aon_exit()` removes every hook and frees all the armed entries.

## Run time

**Goal:** for a protected program, the kernel module must arm a thread when it passes an ingress gate, allow a `syscall` only at an egress gate reached by an armed thread (and disarm it there), refuse every other `syscall`, and disarm a thread before a signal handler runs.

The module only looks at the two gates of each block, and at signals:

| Event          | Hook         | Symbol                 | Handler              | Source                                            |
| -------------- | ------------ | ---------------------- | -------------------- | ------------------------------------------------- |
| ingress gate   | die notifier | `notify_die()` (#UD)   | `aon_die()`          | [`kernel/aon_enforce.c`](../kernel/aon_enforce.c) |
| egress gate    | kprobe       | `x64_sys_call()`       | `aon_syscall_pre()`  | [`kernel/aon_enforce.c`](../kernel/aon_enforce.c) |
| signal handler | kprobe       | `x64_setup_rt_frame()` | `aon_sigframe_pre()` | [`kernel/aon_enforce.c`](../kernel/aon_enforce.c) |

Every hook first checks `aon_region_any()`, a simple counter. When no protected program is running, that check is all the module costs.

### Ingress gate: `ud2` → arm

**Hook:** die notifier, registered with `register_die_notifier()` and called through `notify_die()` → handler `aon_die()`.

`ud2` causes #UD, the "invalid instruction" fault. The kernel tells every registered die notifier about it before sending a signal; `aon_die()` only acts on `DIE_TRAP` with `X86_TRAP_UD`:

| Where the `ud2` is                                    | What the module does                                                                                                                                                         |
| ----------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| in user code, **inside** the process's AoN region     | **arms** the thread (adds its tid to the armed table), moves RIP past the 2-byte `ud2` and hides the fault (`NOTIFY_STOP`). The thread goes on with the body, with no signal |
| **outside** the AoN region, or an unprotected process | nothing (`NOTIFY_DONE`): the kernel handles the #UD as usual and sends SIGILL                                                                                                |

The armed state is just **one bit per thread**: arming a thread that is already armed changes nothing.

### Egress gate: `syscall` → check and disarm

**Hook:** kprobe on `x64_sys_call()` → handler `aon_syscall_pre()`.

Every 64-bit system call goes through `x64_sys_call()`, which picks the kernel function for the system call nr. The module finds the `syscall` instruction that entered the kernel from the saved user RIP. RIP points to the next instruction, so the `syscall` is at `RIP - 2`.

| Where the `syscall` is              | Armed? | Result                                                                                    |
| ----------------------------------- | ------ | ----------------------------------------------------------------------------------------- |
| unprotected process (no AoN region) | —      | allowed, not checked                                                                      |
| **inside** the AoN region           | yes    | **disarm** and allow: the block ran from its ingress gate to its egress gate              |
| **inside** the AoN region           | no     | refused: **unarmed egress gate** (vector A, property A2)                                  |
| **outside** the AoN region          | —      | refused: not an egress gate (vector B, the vDSO fallback, any stray `0f 05`; property B1) |

Because the thread is disarmed at every allowed egress gate, **one ingress allows only one egress**.

A refused system call does not run. By default (`neutralize_mode=1`) the module replaces the system call nr with an invalid one, so the program gets `-ENOSYS`, and the module logs `BLOCKED system call nr=… at syscall 0x… (reason)`. The thread keeps running, and the program decides what to do with the error.

### Signal rule: disarm before a handler

**Hook:** kprobe on `x64_setup_rt_frame()` → handler `aon_sigframe_pre()`.

A signal can arrive while a thread is armed, between the ingress and the egress gate. If the thread stayed armed, the signal handler (or a fake signal frame) could reach an egress gate without passing its ingress gate. So the module hooks `x64_setup_rt_frame()`, which the kernel calls only when it is about to run a signal handler (it builds the handler's frame on the user stack), and `aon_sigframe_pre()` **disarms** the thread there. `rt_sigreturn` never arms it again.

The cost: when the handler returns, the interrupted block reaches its egress gate unarmed and is refused, so the caller has to run the block again. The gain: a handler can never reuse an egress gate, whether the thread it interrupted was armed or not.

## The state the module keeps

All of it is in [`kernel/aon_state.c`](../kernel/aon_state.c). The hooks run in places where the kernel cannot wait, so both tables are protected by spinlocks (with `irqsave`) and memory is allocated with `GFP_ATOMIC`.

|               | AoN regions                                                         | Armed state                                                                                            |
| ------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| One entry per | address space (`mm`)                                                | thread (tid)                                                                                           |
| Stored in     | a fixed array of 64 slots `{mm, start, end}`, searched one by one   | a hashtable with 1024 buckets (`DEFINE_HASHTABLE(armed_ht, 10)`); a thread is armed if it has an entry |
| Added at      | exec (note found), fork (copy)                                      | ingress gate (`kmalloc` of one entry)                                                                  |
| Read at       | ingress gate, egress gate                                           | egress gate, signal delivery                                                                           |
| Removed at    | `exit_mmap()` (slot marked free)                                    | egress gate, signal delivery, `do_exit()` (`kfree` of the entry), module unload                        |
| If it fails   | table full: the region is not saved, the program is killed (SIGILL) | `kmalloc` fails: the thread is not armed, its egress gate is refused                                   |

In both cases a failure can stop a protected program, but it can never let a system call through.

## Example: a hijacked thread

Take a protected program whose AoN region has only the blocks of its required system calls, and `execve` is not one of them. An attacker takes control of a thread: they choose its registers and where it jumps next. They want to invoke `execve` (nr 59), so they set `eax = 59` and the arguments, and jump to a site. Every choice fails:

| Jump target                                                                             | What the module sees                                                   | Result                                                                                  |
| --------------------------------------------------------------------------------------- | ---------------------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| the `syscall` of `__aon_read` (**vector A**, aligned gadget)                            | a `syscall` inside the AoN region, thread not armed (it skipped `ud2`) | refused: unarmed egress gate                                                            |
| a `0f 05` hidden inside an ordinary function in `.text` (**vector B**, misaligned site) | a `syscall` outside the AoN region                                     | refused: outside the AoN region                                                         |
| the `ud2` of `__aon_read` (reusing the whole block)                                     | an ingress gate, then its egress gate                                  | allowed, but the body sets `eax` back to 0: the kernel runs `read`, not `execve`        |
| some other `ud2` in the region                                                          | —                                                                      | there is none: the verifier checked that every `0f 0b` in the region is an ingress gate |

The two refusals appear in the kernel log like this:

```
aon: pid=… comm=…: protecting [start, end)                                       # at exec
aon: BLOCKED system call nr=59 at syscall 0x… (unarmed egress gate) (pid=… comm=…)    # vector A
aon: BLOCKED system call nr=59 at syscall 0x… (outside the AoN region) (pid=… comm=…) # vector B
```

In both cases `execve` never runs: the thread gets `-ENOSYS` and goes on. An unprotected program (built without `-DAON_DEFEND`, so without a note) is never checked, and the same jumps work even with the module loaded.

## What the defense does not cover

- **Reusing a whole wrapper.** The body fixes the system call nr but does not check the arguments (on purpose). An attacker who jumps to an ingress gate runs a real block, with arguments they choose. What they can no longer do is invoke a system call the program never needed: a program that never calls `execve` has no `execve` block at all.
- **Other ways into the kernel.** The module only watches `x64_sys_call()`. The 32-bit and x32 entries (`int $0x80`, `sysenter`, a `syscall` with `__X32_SYSCALL_BIT`) do not go through it, and neither do 32-bit and x32 signal frames.
- **Changes to the AoN region.** The module assumes the bytes of the region stay the ones checked at build time. It does not stop the program from changing or remapping them (for example `mprotect` and then a write). Doing that, though, needs system calls, and those must pass through an egress gate too.
- **Programs started before the module was loaded** are not protected. **Dynamic executables** cannot be protected: their loader and shared libraries make system calls from outside the executable's AoN region.
