# How the AoN defense works

## Background

An **AoN block** is a system call wrapper that a thread can only run from its first instruction:

```
__aon_read:   ud2                 # ingress gate
              mov  $0, %eax       # body: sets the system call nr (read)
              syscall             # egress gate
              ret                 # outside the block: ordinary return
```

- **Ingress gate** (`ud2`): the kernel **arms** the thread, i.e. it records that the thread entered the block.
- **Egress gate** (`syscall`): the kernel allows the system call only if the thread is armed, then **disarms** it.
- **AoN region**: the memory range that holds all the AoN blocks of a program, and nothing else.
- **Site**: any place where a `syscall` instruction can run.

A **protected** program can invoke a system call only by running a block from its ingress gate to its egress gate. This stops two attacks:

- **vector A, aligned gadget**: jumping straight to the `syscall` of a block, skipping `ud2` → refused, the thread is not armed;
- **vector B, misaligned site**: jumping to bytes `0f 05` hidden inside another instruction → refused, it is outside the AoN region.

How the PoC mounts both attacks is in [`attack.md`](attack.md).

A program is **defended** when it is built with the AoN blocks and an ELF note that says where they are. It is **protected** when it runs with the kernel module loaded.

| When             | Part                    | Source                                                                                           | What it does                                                         |
| ---------------- | ----------------------- | ------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------- |
| Build            | **hardened library**    | [`aonlibc/nolibc/`](../aonlibc/nolibc/), [`aonlibc/aon_syscalls.S`](../aonlibc/aon_syscalls.S)   | a small C library whose wrappers are AoN blocks                      |
| Build            | **verifier**            | [`tools/verify_aon.py`](../tools/verify_aon.py)                                                  | checks there is no `ud2` in the region except the ingress gates      |
| Startup/teardown | **kernel module**       | [`kernel/aon_lifecycle.c`](../kernel/aon_lifecycle.c), [`kernel/aon_elf.c`](../kernel/aon_elf.c) | reads the note, saves the region, copies it at fork, drops it at exit |
| Run              | **kernel module**       | [`kernel/aon_enforce.c`](../kernel/aon_enforce.c), [`kernel/aon_state.c`](../kernel/aon_state.c) | arms at the ingress gate, checks and disarms at the egress gate      |

## Requirements

Code and docs cite the requirements of the thesis by label, for example `(B2)` next to the unarmed-egress-gate check. **B1–B5** are what the AoN mechanism needs, with no reference to system calls. **D1–D4** are what system call hardening built on it needs.

| Req. | The thesis requires that…                                                                                          | Realized in the PoC by                                                                                      |
| ---- | ------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------- |
| B1   | the kernel intercepts both gates of every AoN block, and accepts a gate only at the address of a gate of a block   | `ud2` caught through #UD, `syscall` caught at `x64_sys_call`; gates accepted only inside the AoN region, which the verifier checks |
| B2   | the kernel detects every **unintended execution** of a block (egress gate without its ingress gate and body), before the egress gate's operation runs | per-thread armed state, set at the ingress gate, consumed at the egress gate (**vector A**)                 |
| B3   | the kernel gets the information that identifies the blocks before the program's first instruction, and it cannot be changed afterward | one region, ELF note read at exec; region and armed state only in kernel memory, no interface to change them |
| B4   | the body of every block has no explicit control transfer (**static condition**)                                    | blocks written in assembly, body = one `movl`                                                               |
| B5   | no implicit control transfer lets an armed thread continue elsewhere or with other registers (**dynamic condition**) | the signal rule: disarm before a handler, never re-arm at `rt_sigreturn`                                   |
| D1   | the library executes `syscall` only in bijective wrappers, each of which can be included individually              | the `sys_*` functions in `aon_syscalls.S`, one section per wrapper                                          |
| D2   | the build includes in the binary only the required wrappers                                                        | static linking with `--gc-sections -z start-stop-gc`                                                        |
| D3   | every wrapper is an AoN block: ingress gate before the body that pins the number, egress gate = its `syscall`       | `ud2 ; movl $nr,%eax ; syscall` for every wrapper                                                           |
| D4   | the kernel detects every system call invocation that does not come from an egress gate                             | every 64-bit `syscall` outside the AoN region refused (**vector B**)                                        |

D1–D4 give the thesis' four properties: **P1** every wrapper is bijective and individually includable, **P2** every wrapper in the binary is required, **P3** every wrapper is hardened, **P4** every invocation outside a wrapper's `syscall` is detected. Together, P2–P4 give **L1**: the process can invoke only its required system calls.

Labels that are *not* requirements: the evaluation rows **C1–C5**, **S1–S4** (security) and **P0–P3** (cost) in [`evaluation.md`](evaluation.md) are just row IDs. In particular, the cost rows P0–P3 are unrelated to the properties P1–P4.

## Build time

**Goal:** every system call goes through an AoN block, only the needed blocks are included, they are all in one region described by an ELF note, and the region has no `ud2` except the ingress gates.

### The base library: nolibc

The hardened library ([`aonlibc/`](../aonlibc/README.md)) is built on **nolibc**, the small C library that ships with the Linux kernel sources. It is made only of headers, is meant for static linking, and makes every system call through its own `sys_*` raw wrappers, so all of them can be replaced by AoN blocks.

Each system call has two layers in [`nolibc/sys.h`](../aonlibc/nolibc/sys.h):

- the **public function** (`read()`, …), which the program calls. It calls the raw wrapper and turns a negative result into `errno` and `-1`;
- the **raw wrapper** (`sys_read()`, …), which runs the `syscall`.

The original nolibc code for `read`, simplified:

```c
static ssize_t sys_read(int fd, void *buf, size_t count)
{
	register long rax __asm__("rax") = __NR_read;    /* system call nr = 0 (read) */
	register long rdi __asm__("rdi") = fd;           /* 1st argument */
	register long rsi __asm__("rsi") = (long)buf;    /* 2nd argument */
	register long rdx __asm__("rdx") = count;        /* 3rd argument */

	__asm__ volatile ("syscall"                      /* its own syscall, in the caller's code */
	                  : "+a"(rax)
	                  : "r"(rdi), "r"(rsi), "r"(rdx)
	                  : "rcx", "r11", "memory");
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

With `-DNOLIBC_AON`, `sys.h` only declares the raw wrappers as `extern`, and the linker connects them to the AoN blocks in [`aon_syscalls.S`](../aonlibc/aon_syscalls.S). The public functions do not change, so the program's source stays the same and `errno` handling stays outside the blocks.

```c
#ifdef NOLIBC_AON
extern ssize_t sys_read(int fd, void *buf, size_t count);   /* the AoN block, in aon_syscalls.S */
#else
static ssize_t sys_read(int fd, void *buf, size_t count) { ... }   /* original nolibc */
#endif

ssize_t read(int fd, void *buf, size_t count)
{
	return __sysret(sys_read(fd, buf, count));       /* errno translation, outside the block */
}
```

The AoN block for `read`:

```asm
	.section	aon_text, "ax", @progbits, unique, 2
sys_read:
__aon_read:
	ud2				/* INGRESS GATE, only with -DAON_DEFEND */
	movl	$0, %eax		/* body: system call nr = 0 (read)       */
	syscall				/* EGRESS GATE                           */
	ret				/* outside the block: back to the caller */
```

- `sys_read` and `__aon_read` are the same address, so `call sys_read` lands on the ingress gate.
- The body only sets the nr: C and Linux system calls use the same registers for the first three arguments (`rdi`, `rsi`, `rdx`) and the return value (`rax`).
- The 4th argument differs (`rcx` in C, `r10` for the kernel). A wrapper with four or more arguments has a small stub outside the region that copies `rcx` to `r10` and jumps to the ingress gate. It has no `syscall`, so it gives an attacker nothing.
- The fields of `.section aon_text, "ax", @progbits, unique, 2` are explained in [`ELF-note.md`](ELF-note.md), "How the note is produced".

### AoN region

All the blocks are placed next to each other:

```
__start_aon_text:
__aon_open:   ud2 ; mov $2, %eax ; syscall ; ret
__aon_read:   ud2 ; mov $0, %eax ; syscall ; ret
              …                    # one block per required system call
__stop_aon_text:                   # first byte after the last block
```

- **One section.** The linker joins all the `aon_text` sections into one and marks it with `__start_aon_text` and `__stop_aon_text`.
- **Only the needed blocks.** Each block is in its own section, so `--gc-sections` drops the ones the program never calls. `-z start-stop-gc` stops the note's reference to the two symbols from keeping them all.
- **Nothing else inside.** Only blocks and their `ret`, so "inside the region" means "inside a block".
- **Described by a note.** The `.note.aon` ELF note stores the region's limits as offsets from the note itself, so they are right wherever the program is loaded.

Details are in [`ELF-note.md`](ELF-note.md).

### Static linking

A defended program is linked with `-nostdlib -static`: no system C library, and all code is in the executable. This matters because the module refuses every `syscall` outside the one AoN region:

- a **dynamic loader** runs its own `syscall`s before the program starts;
- a **shared C library** has its own `syscall`s, in its own memory;
- the **vDSO** has a fallback `syscall` (nolibc never uses it).

All of these would be outside the region and refused. With static linking, every `syscall` is in a block of the executable. (`-no-pie` is also used, but the defense does not need it.)

### The verifier

At an ingress gate, the module only checks that the `ud2` is inside the region. So the region must have no other `0f 0b`, not even a misaligned one hidden inside another instruction: it would let an attacker arm a thread and then jump to any egress gate.

[`verify_aon.py`](../tools/verify_aon.py) reads the executable's symbols and:

1. finds the region (`__start_aon_text`, `__stop_aon_text`) and the ingress gates (`__aon_*`);
2. looks for `0f 0b` at **every byte** of the region;
3. fails if any of them is not an ingress gate.

### The defended build

1. **compile** the program with `-DNOLIBC_AON`: the public functions call the AoN blocks;
2. **assemble** `aon_syscalls.S` with `-DAON_DEFEND`: the blocks get their `ud2` and the note is added. Both flags are needed;
3. **link** with `-nostdlib -static -Wl,--gc-sections -Wl,-z,start-stop-gc`;
4. **verify** with `verify_aon.py`, and check with `readelf -n` that the note is there.

The result: one executable whose every `syscall` is in an AoN block, with only the needed blocks, in one region described by a note, and with no stray `ud2`.

## Startup and teardown time

**Goal:** when a program starts, read its note and save its region for its address space (`mm`, the kernel's structure for a process's memory, shared by its threads). Then keep this state right: copy it at fork, and remove it when the address space or thread goes away.

Only programs started **after** the module was loaded are protected.

| Event                               | Hook                     | Symbol               | Handler               |
| ----------------------------------- | ------------------------ | -------------------- | --------------------- |
| exec                                | kprobe                   | `finalize_exec()`    | `aon_exec_pre()`      |
| exec (before the first instruction) | task_work (`TWA_RESUME`) | —                    | `aon_exec_scan()`     |
| fork, clone                         | kprobe                   | `wake_up_new_task()` | `aon_fork_pre()`      |
| address space destroyed             | kprobe                   | `exit_mmap()`        | `aon_exit_mmap_pre()` |
| thread exit                         | kprobe                   | `do_exit()`          | `aon_do_exit_pre()`   |

All in [`kernel/aon_lifecycle.c`](../kernel/aon_lifecycle.c).

### Exec: read the note

`finalize_exec()` runs when the new program is loaded but has not run yet.

1. **Schedule the work.** Reading the program's memory may need to wait, and a kprobe cannot. So `aon_exec_pre()` schedules `aon_exec_scan()` to run just before the thread returns to the program.
2. **Find the note.** `aon_elf_find_region()` reads the program headers already in memory and looks for the `AoN` note (see [`ELF-note.md`](ELF-note.md)).
3. **Use the result.**
   - **note found**: save `[start, end)` for this `mm` and log `protecting [start, end)`. The program is protected.
   - **no note**: an ordinary program, ignored.
   - **broken note or full table**: save nothing. No thread can be armed, so the first `ud2` kills the program with SIGILL.

### Fork: copy the region

- **fork**: the child gets a copy of the parent's region (same addresses, since its memory is a copy).
- **thread or vfork**: nothing to do, the child shares the parent's `mm`.

The armed state is never inherited: it is stored by thread id.

### Exit: remove the state

- **address space destroyed** (exit, or exec replacing it): its region is removed.
- **thread exit**: its armed state is removed, so a reused thread id never starts armed.
- **module unload**: all hooks and armed state are removed. Protected programs still running will die with SIGILL at their next `ud2`.

## Run time

**Goal:** arm a thread at an ingress gate, allow a `syscall` only at an egress gate of an armed thread (and disarm it), refuse every other `syscall`, and disarm a thread before a signal handler.

| Event          | Hook         | Symbol                 | Handler              |
| -------------- | ------------ | ---------------------- | -------------------- |
| ingress gate   | die notifier | `notify_die()` (#UD)   | `aon_die()`          |
| egress gate    | kprobe       | `x64_sys_call()`       | `aon_syscall_pre()`  |
| signal handler | kprobe       | `x64_setup_rt_frame()` | `aon_sigframe_pre()` |

All in [`kernel/aon_enforce.c`](../kernel/aon_enforce.c). Each handler returns at once if no program is protected, but the hook on `x64_sys_call()` still runs on every system call in the system.

### Ingress gate: `ud2` → arm

`ud2` raises #UD, the invalid-instruction fault, and the kernel passes it to `aon_die()` before sending a signal.

| Where the `ud2` is                             | What the module does                                                          |
| ---------------------------------------------- | ----------------------------------------------------------------------------- |
| **inside** the AoN region                      | arms the thread, skips the 2-byte `ud2`, and hides the fault: no signal        |
| **outside**, or in an unprotected program      | nothing: the kernel sends SIGILL as usual                                     |

### Egress gate: `syscall` → check and disarm

Every 64-bit system call goes through `x64_sys_call()`. The module finds the `syscall` at the saved user RIP minus 2.

| Where the `syscall` is     | Armed? | Result                                     |
| -------------------------- | ------ | ------------------------------------------ |
| unprotected program        | —      | allowed                                    |
| **inside** the AoN region  | yes    | **disarm** and allow                       |
| **inside** the AoN region  | no     | refused: unarmed egress gate (vector A)    |
| **outside** the AoN region | —      | refused: not an egress gate (vector B)     |

So one ingress allows exactly one egress. A refused system call does not run: the program gets `-ENOSYS`, and the module logs `BLOCKED system call nr=… (reason)`.

### Signal rule: disarm before a handler

A signal can arrive between the ingress and the egress gate. If the thread stayed armed, the handler could reach an egress gate without its ingress gate. So `aon_sigframe_pre()` disarms the thread just before the handler runs, and `rt_sigreturn` never re-arms it. The armed state lives in the kernel, so a forged signal frame cannot arm a thread either.

The cost: the interrupted system call fails with `-ENOSYS`, and the program must call it again.

## The state the module keeps

In [`kernel/aon_state.c`](../kernel/aon_state.c), protected by spinlocks:

|              | AoN regions                         | Armed state                                  |
| ------------ | ----------------------------------- | -------------------------------------------- |
| One entry per | address space (`mm`)               | thread                                       |
| Stored in    | fixed array of 64 slots             | hashtable; armed = has an entry              |
| Added at     | exec, fork                          | ingress gate                                 |
| Removed at   | address space destroyed             | egress gate, signal, thread exit, unload     |
| If it fails  | table full: program killed (SIGILL) | no memory: thread not armed, `syscall` refused |

A failure can stop a protected program, but never lets a system call through.

## Example: a hijacked thread

An attacker controls a thread of a protected program that has no `execve` block. They set `eax = 59` (`execve`) and jump:

| Jump target                                 | Result                                                          |
| ------------------------------------------- | --------------------------------------------------------------- |
| the `syscall` of `__aon_read` (vector A)    | refused: unarmed egress gate                                    |
| a hidden `0f 05` in `.text` (vector B)      | refused: outside the AoN region                                 |
| the `ud2` of `__aon_read`                   | allowed, but the body sets `eax = 0`: `read` runs, not `execve` |
| another `ud2` in the region                 | there is none, the verifier checked                             |

Kernel log:

```
aon: pid=… comm=…: protecting [start, end)
aon: BLOCKED system call nr=59 at syscall 0x… (unarmed egress gate) (pid=… comm=…)
aon: BLOCKED system call nr=59 at syscall 0x… (outside the AoN region) (pid=… comm=…)
```

An unprotected program is never checked, so the same jumps work there.

## What the defense does not cover

- **Reusing a whole block.** Arguments are not checked, so an attacker can run a real block with their own arguments. They cannot invoke a system call the program never uses.
- **Other ways into the kernel.** Only `x64_sys_call()` is watched; 32-bit entries (`int $0x80`, `sysenter`) and x32 are not.
- **Changes to the region.** The module does not stop the program from rewriting or remapping it (e.g. with `mprotect`), though that needs system calls through egress gates.
- **Programs started before the module was loaded**, and **dynamic executables**, are not protected.
