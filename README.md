# All-or-Nothing

Proof of concept for the master's thesis **"All-or-Nothing Code Blocks: A
Kernel-Enforced Primitive for Indivisible Execution and Its Application to
Syscall Site Hardening"**.

An **All-or-Nothing (AoN) block** is a code block that a thread can only run
from its first instruction to its last. Here every system call wrapper becomes
one:

```
ud2                 # ingress gate: the kernel arms the thread
mov  $nr, %eax      # body: pins the system call number
syscall             # egress gate: allowed only if armed, then disarmed
ret
```

A kernel module enforces it. A protected program can then invoke a system
call only by running a whole wrapper. The two code-reuse vectors are both
refused:

- **vector A**: jumping straight onto a wrapper's `syscall`, which reaches an
  unarmed egress gate;
- **vector B**: jumping onto a misaligned `0f 05` hidden in other code, which
  is outside the AoN region.

How the two attacks are built is in
[`documentation/attack.md`](documentation/attack.md).

This is an academic, defensive PoC. The attacker is simulated, it runs only
local, harmless programs (`/bin/echo`), and nothing in the repository targets
real software.

## Repository

| Directory        | Content                                                                             |
| ---------------- | ----------------------------------------------------------------------------------- |
| `aonlibc/`       | the hardened syscall library: vendored nolibc + the AoN wrappers (`aon_syscalls.S`) |
| `kernel/`        | the kernel module `aon_mod.ko`                                                      |
| `tools/`         | the build-time verifier `verify_aon.py`                                             |
| `user/cat/`      | scenario: vectors A and B against a minimal `cat`                                   |
| `user/signal/`   | scenario: the signal rule                                                           |
| `evaluation/`    | correctness, security and cost evaluation                                           |
| `documentation/` | the guides below                                                                    |

## Quick start

On x86_64 Linux with the headers of the running kernel:

```bash
make all
```

```bash
sudo insmod kernel/aon_mod.ko
```

```bash
make -C user/cat run defend-run
```

The baseline `cat` lets both attacks through (`/bin/echo` replaces the
process); `cat_defended` refuses them and exits 3.

## Documentation

| File                                                             | Content                                                                            |
| ---------------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| [`documentation/repository.md`](documentation/repository.md)     | directories, Makefiles, targets and usage of every part                            |
| [`documentation/requirements.md`](documentation/requirements.md) | platform, kernel, toolchain, Python and evaluation tools                           |
| [`documentation/defense.md`](documentation/defense.md)           | **start here** how the defense works: build time, exec/fork/exit, run time, limits |
| [`documentation/ELF-note.md`](documentation/ELF-note.md)         | the `.note.aon` record that tells the kernel where the AoN region is               |
| [`documentation/attack.md`](documentation/attack.md)             | **continue here** vectors A and B, and the simulated vulnerabilities they use      |
| [`documentation/evaluation.md`](documentation/evaluation.md)     | how the evaluation works: rows, scripts, judging, batch means                      |
