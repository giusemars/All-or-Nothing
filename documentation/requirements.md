# Requirements

What is needed to build and run each part of the repository. The versions in
the tables are those of the development machine (Debian 13,
`6.12.73+deb13-amd64`), not minimums, unless stated otherwise. See
[`repository.md`](repository.md) for what each part is.

## Platform

- **x86_64 Linux.** The wrappers, the attacker primitives and the module are
  x86_64-specific (`ud2`, `syscall`, the x86 #UD vector, the x86_64 signal
  frame).
- **Root**, to load and unload `aon_mod` (`insmod`, `rmmod`) and to read the
  kernel log (`dmesg`). Both evaluation scripts call `sudo` themselves.

## Kernel

`aon_mod` is an out-of-tree module that hooks the running kernel with
kprobes and a die notifier; it needs no kernel patch, but the kernel must
offer the following.

| Requirement | Why |
| --- | --- |
| `CONFIG_MODULES=y`, and unsigned modules accepted (`CONFIG_MODULE_SIG_FORCE` not set, Secure Boot lockdown off) | `aon_mod.ko` is built locally and not signed |
| `CONFIG_KPROBES=y` | every hook except the ingress gate is a kprobe |
| kprobe-able symbols `x64_sys_call`, `x64_setup_rt_frame`, `finalize_exec`, `wake_up_new_task`, `exit_mmap`, `do_exit` | the egress gate check, the signal rule, and exec / fork / exit tracking. `x64_sys_call` exists since Linux 6.9; on older kernels the module does not load |
| headers of the running kernel (Debian: `linux-headers-$(uname -r)`), i.e. `/lib/modules/$(uname -r)/build` | `kernel/Makefile` builds against them |

Developed and tested on `6.12.73+deb13-amd64` only.

## Build toolchain

Needed by `make all` and by every Makefile in the repository.

| Tool | Used for | Tested with |
| --- | --- | --- |
| `gcc` | C and assembly (`.S`, AT&T syntax through GNU `as`) of the scenarios and the benchmark; the module (must match the compiler of the running kernel) | 14.2.0 |
| GNU binutils: `as`, `ld`, `readelf` | `-z start-stop-gc` (binutils 2.37 or newer); `readelf -n` checks the `.note.aon` of every defended build | 2.44 |
| GNU `make` | all Makefiles | 4.4.1 |
| `python3` | `tools/verify_aon.py`, run on every defended build | 3.13.5 |

No libc is needed for the scenarios or the benchmark: they link the vendored
nolibc in `aonlibc/nolibc/` (`-nostdlib -static`). The two P0 programs of the
cost block (`evaluation/cost/syscall_latency.c`, `tsc_calib.c`) are ordinary
glibc programs and need the glibc development files (Debian `libc6-dev`).

## Python

**Python 3.7 or newer**, for the Python scripts of the repository:

| Script | Needs |
| --- | --- |
| `tools/verify_aon.py` (build-time verifier, run on every defended build) | standard library only (`dataclasses`: 3.7) |
| `evaluation/security/analyze_binary.py`, `evaluation/security/summarize.py` | standard library only (`subprocess.run(capture_output=...)`: 3.7) |
| `evaluation/cost/batch_means.py`, `evaluation/cost/analyze_cost.py` | `numpy`, `scipy` (`scipy.stats`) |

The cost evaluation is the only part that needs third-party packages; it was
run with numpy 2.2.4 and scipy 1.15.3 (Debian `python3-numpy`,
`python3-scipy`) on Python 3.13.

## Evaluation

Besides the toolchain and Python above, the evaluation scripts use:

| Tool | Used by | Note |
| --- | --- | --- |
| `sudo` | both scripts | `run_security.sh` honors `AON_SUDO` instead; either runs without it as root |
| `git` | both scripts | records commit and branch; `run_cost.sh` names its results directory after them |
| `strace` | `run_security.sh` | `strace -n -k` needs a build with stack tracing (libdw or libunwind; Debian's has it). Tested with 6.13 |
| `objdump`, `nm` | `run_security.sh`, `analyze_binary.py` | binutils |
| `taskset` | `run_cost.sh` | util-linux; pins the measured process to `CPU` |
| `systemd-detect-virt` | both scripts | optional, only recorded in `environment.txt` |

The cost block also needs a CPU with `rdtscp` and a constant, invariant TSC
(`constant_tsc`, `nonstop_tsc` in `/proc/cpuinfo`): every sample is a TSC
delta, converted to ns by `tsc_calib`.
