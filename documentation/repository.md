# Repository guide

What each directory holds, what each Makefile builds, and how to use the
pieces. For how the defense itself works see [`defense.md`](defense.md); for
the `.note.aon` record see [`ELF-note.md`](ELF-note.md); for the attacks
see [`attack.md`](attack.md); for how the
evaluation works see [`evaluation.md`](evaluation.md); for the toolchain
and Python packages see [`requirements.md`](requirements.md).

## Overview

```
All-or-Nothing/
├── Makefile              top level: builds everything below
├── aonlibc/              the hardened system call library (no Makefile)
│   ├── nolibc/           vendored nolibc (Linux v6.12), patched for -DNOLIBC_AON
│   └── aon_syscalls.S    the hardened named wrappers (baseline or AoN blocks)
├── user/                 the PoC scenarios (victim + simulated attacker)
│   ├── cat/              vectors A and B against a minimal `cat`
│   └── signal/           the signal rule, both sides
├── kernel/               the AoN kernel module, aon_mod.ko
├── tools/
│   └── verify_aon.py     the build-time verifier
├── evaluation/
│   ├── bench/            cost benchmark program (no attack)
│   ├── security/         correctness + security rows C1–C5, S1–S4
│   ├── cost/             cost rows P0–P3
│   └── results/          output of both (empty until a run)
└── documentation/        this guide, requirements.md, defense.md,
                          attack.md, evaluation.md, ELF-note.md
```

The three components of the thesis map onto the tree as follows:

| Component           | Where                 |
| ------------------- | --------------------- |
| hardened library    | `aonlibc/`            |
| kernel module       | `kernel/`             |
| build-time verifier | `tools/verify_aon.py` |

Everything in `user/` and `evaluation/` is built on top of these three.

## Quick start

From the repository top:

```bash
make all
```

```bash
sudo insmod kernel/aon_mod.ko
```

```bash
make -C user/cat run defend-run
```

```bash
make -C user/signal run defend-run
```

The baseline runs (`run`) show both attacks succeeding (`/bin/echo` replaces
the process); the defended runs (`defend-run`) show them refused (exit 3).
Unload the module with `sudo rmmod aon_mod` (or `make -C kernel unload`).

## Build model

All user-space binaries share one build recipe; it is repeated in each
Makefile so each directory stays self-contained (no sub-make, no shared
include).

- **One source, two variants.** `aonlibc/aon_syscalls.S` is assembled twice:
  without `-DAON_DEFEND` into `aon_syscalls.o` (baseline: plain
  `mov $nr,%eax ; syscall ; ret`) and with it into `aon_syscalls.aon.o`
  (defended: each wrapper is the AoN block `ud2 ; mov $nr,%eax ; syscall`
  plus a `ret` outside it, and the `.note.aon` descriptor of the AoN region).
  The C objects are the same in both builds.
- **Compile flags.** `-fno-pie` (fixed load address), `-fcf-protection=none`
  (no CET markings), `-ffunction-sections -fdata-sections` (so unused code
  can be dropped), `-I aonlibc/nolibc -DNOLIBC_AON` (nolibc's `sys_open`,
  `sys_read`, `sys_write`, `sys_close`, `sys_lseek`, `sys_exit` become
  `extern` and bind to `aon_syscalls.S`). Scenarios use `-O0`, the benchmark
  `-O2`.
- **Link flags.** `-nostdlib -static -no-pie -Wl,--gc-sections
  -Wl,-z,start-stop-gc`: only nolibc's startup and the wrappers of the
  required system calls are linked. `-z start-stop-gc` is required: without
  it the note's reference to `__start_aon_text`/`__stop_aon_text` would keep
  every AoN block.
- **Post-link checks (defended only).** After linking a `*_defended` binary
  the Makefile runs `tools/verify_aon.py` (no stray `ud2` in the AoN region
  besides the ingress gates) and `readelf -n` (the `.note.aon` survived
  `--gc-sections`); if either fails the binary is deleted and the build
  fails.
- **Running a defended binary needs `aon_mod`.** Without the module the
  ingress gate's `ud2` is an ordinary #UD and the process dies with
  `SIGILL`. The baseline binaries carry no note, so the module never
  polices them, loaded or not.

## Directories

### Top level

| File                  | Role                                                                                                                      |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| `Makefile`            | convenience targets, see below                                                                                            |
| `.clangd`, `.vscode/` | editor/LSP configuration only, not used by the build; `compile_commands.json` files are generated locally and not tracked |

**`Makefile`**

| Target              | Does                                                                                                                         |
| ------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| `make` / `make all` | `user/cat`: `cat cat_defended`; `user/signal`: `sig sig_defended`; `evaluation/bench`: all four builds; `kernel`: the module |
| `make clean`        | `make clean` in `user/cat`, `user/signal`, `evaluation/bench`, `kernel`                                                      |

### `aonlibc/` — the hardened system call library

No Makefile on purpose: each consumer compiles these sources directly (see
[Build model](#build-model)). How the wrappers and the AoN region are built
is in [`defense.md`](defense.md#build-time).

| File             | Role                                                                                                                                                                                                                                                                                                                                                      |
| ---------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `nolibc/`        | vendored nolibc from Linux v6.12 `tools/include/nolibc`; one patch in `sys.h` makes the six `sys_*` wrappers `extern` under `-DNOLIBC_AON`. Each of the six patched sites is commented `PoC patch:`, so `grep -n 'PoC patch' aonlibc/nolibc/sys.h` lists them; without `-DNOLIBC_AON` it is ordinary nolibc                                               |
| `aon_syscalls.S` | the hardened named wrappers. File I/O + exit: `sys_open`, `sys_read`, `sys_write`, `sys_close`, `sys_exit` (cat's intended system calls) and `sys_lseek` (benchmark only). Signals: `sys_rt_sigaction`, `sys_setitimer`, `sys_rt_sigreturn` (the AoN `SA_RESTORER`). Each block is its own `aon_text` input section, so only the required ones are linked |

To add a wrapper, add a block to `aon_syscalls.S` following the existing
ones; a program that calls it will link it in, and no other program will.

### `user/cat/` — vectors A and B

A minimal `cat` (`open` → `read` loop → `write` to stdout → `close`) and the
simulated attacker whose goal is `execve` (nr 59), not an intended system
call. How the attacks work in [`attack.md`](attack.md). This directory is also the
template for new scenarios.

| File             | Role                                                                                   |
| ---------------- | -------------------------------------------------------------------------------------- |
| `cat.c`, `cat.h` | the victim and the attack driver                                                       |
| `gadget.S`       | `benign_compute`, an ordinary routine whose bytes hide a misaligned `0f 05` (vector B) |
| `attacker.S`     | `hijack`, the simulated attacker primitive (sets registers, redirects control flow)    |
| `reset.sh`       | rewrites `victim.txt` with its demo content (`./reset.sh [FILE]`)                      |
| `Makefile`       | see below                                                                              |

**`Makefile`** (run from `user/cat/`)

| Target              | Does                                                                     |
| ------------------- | ------------------------------------------------------------------------ |
| `make` / `make cat` | baseline `./cat`                                                         |
| `make cat_defended` | defended `./cat_defended`, then verifier + note check                    |
| `make run`          | `reset.sh`, then `./cat victim.txt`, `./cat aligned`, `./cat misaligned` |
| `make defend-run`   | same three with `./cat_defended` (load `aon_mod` first)                  |
| `make clean`        | removes binaries, objects and `victim.txt`                               |

**Usage:** `./cat <filename|aligned|misaligned>` (same for `./cat_defended`).

| Operand                                                                           | Baseline `./cat`                                | Defended `./cat_defended` + `aon_mod`                  |
| --------------------------------------------------------------------------------- | ----------------------------------------------- | ------------------------------------------------------ |
| any file name                                                                     | prints the file                                 | prints the file (same output)                          |
| `aligned` (vector A: jump onto `sys_read_egress`, the read wrapper's egress gate) | `execve` runs, `/bin/echo` replaces the process | refused: unarmed egress gate (B2), exit 3              |
| `misaligned` (vector B: jump onto the misaligned `syscall` in `gadget.S`)         | `execve` runs                                   | refused: `syscall` outside the AoN region (D4), exit 3 |

### `user/signal/` — the signal rule

Same layout as `cat` (no `gadget.S`, no `reset.sh`). One single-stepped
`write` (`EFLAGS.TF`, so a `SIGTRAP` is delivered mid-wrapper) drives three
operands. Details in
[`evaluation.md`](evaluation.md#sig).

| File             | Role                                                                                                   |
| ---------------- | ------------------------------------------------------------------------------------------------------ |
| `sig.c`, `sig.h` | the program and its `SIGTRAP` handler; uses `sys_rt_sigaction` and the AoN `sys_rt_sigreturn` restorer |
| `attacker.S`     | `hijack`, as in `cat`                                                                                  |
| `Makefile`       | see below                                                                                              |

**`Makefile`** (run from `user/signal/`)

| Target              | Does                                                    |
| ------------------- | ------------------------------------------------------- |
| `make` / `make sig` | baseline `./sig`                                        |
| `make sig_defended` | defended `./sig_defended`, then verifier + note check   |
| `make run`          | `./sig correctness`, `attack-armed`, `attack-unarmed`   |
| `make defend-run`   | same three with `./sig_defended` (load `aon_mod` first) |
| `make clean`        | removes binaries and objects                            |

**Usage:** `./sig <correctness|attack-armed|attack-unarmed>`.

| Operand          | Baseline                                                               | Defended + `aon_mod`                                                                     |
| ---------------- | ---------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| `correctness`    | first `write` succeeds ("not demonstrated": nothing to disarm), exit 1 | the armed `write`'s egress gate is refused once, the caller retries and succeeds, exit 0 |
| `attack-unarmed` | handler's `execve` runs                                                | refused: a handler is never armed, exit 3                                                |
| `attack-armed`   | handler's `execve` runs                                                | refused: the thread was disarmed before the handler ran, exit 3                          |

### `kernel/` — `aon_mod`

An out-of-tree module, no kernel patch and no user-space API: it finds each
program's AoN region from its `.note.aon` at exec.

| File              | Role                                                                                                                                           |
| ----------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| `aon_main.c`      | module init/exit, wires the pieces together                                                                                                    |
| `aon_lifecycle.c` | exec (kprobe on `finalize_exec`: read the note), fork (copy the region), exit (drop it)                                                        |
| `aon_elf.c`       | locates the AoN note in a freshly exec'd address space                                                                                         |
| `aon_state.c`     | per-mm AoN region table and per-thread armed state                                                                                             |
| `aon_enforce.c`   | ingress gate (#UD die notifier → arm), egress gate (`syscall` check → disarm or refuse), signal rule (kprobe on `x64_setup_rt_frame` → disarm) |
| `aon.h`           | internal interfaces between the files above                                                                                                    |
| `Kbuild`          | `obj-m := aon_mod.o` and its object list                                                                                                       |

**`Makefile`** (run from `kernel/`; builds against `/lib/modules/$(uname -r)/build`)

| Target        | Does                                         |
| ------------- | -------------------------------------------- |
| `make`        | builds `aon_mod.ko`                          |
| `make load`   | builds, then `sudo insmod aon_mod.ko`        |
| `make unload` | `sudo rmmod aon_mod`                         |
| `make reload` | unload + load                                |
| `make clean`  | kbuild clean (keeps `compile_commands.json`) |

**Parameters** (`/sys/module/aon_mod/parameters/`):

| Name                              | Meaning                                                                                                                                                                  |
| --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `neutralize_mode` (rw, default 1) | how a system call is refused: 1 = rewrite the nr so it returns `-ENOSYS` (safe); 0 = skip `x64_sys_call` and return `-EACCES` (depends on the stack layout at the probe) |
| `signal_disarms` (ro)             | how many times the signal rule disarmed a thread; unlike the `aon:` log lines it is not rate limited                                                                     |

Refusals are logged to the kernel log with the prefix `aon:` (`dmesg`).

### `tools/` — the build-time verifier

| File            | Role                                                                                                                                                                                                                                                                        |
| --------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `verify_aon.py` | `verify_aon.py <binary>`: every `0f 0b` (at any offset) inside `[__start_aon_text,__stop_aon_text)` must be an ingress gate (an `__aon_*` symbol). Exit 0 = ok, 1 = stray `ud2`, 2 = usage/ELF error. Standard library only; run automatically by every `*_defended` target |

### `evaluation/` — measurements

How it works, and how to run it, in [`evaluation.md`](evaluation.md). Both blocks need root (they load and unload `aon_mod`) and write into
`evaluation/results/`.

#### `evaluation/bench/` — the benchmark program

A loop of calls to the hardened `write` wrapper, by default
`write(-1, buf, 0)` (the worst case of the relative overhead), or real writes
of `SIZE` bytes to a file kept within `MAX` bytes by an untimed `lseek`.

**`Makefile`** (`-O2`; otherwise the scenario recipe)

| Target              | Builds                                                                          |
| ------------------- | ------------------------------------------------------------------------------- |
| `make` / `make all` | all four below                                                                  |
| `bench`             | baseline wrappers, not policed                                                  |
| `bench_defended`    | AoN blocks + `.note.aon` (verifier + note check)                                |
| `bench_seccomp`     | baseline + seccomp filter on the system call nr                                 |
| `bench_seccomp_ip`  | as above, each nr also pinned to its wrapper's `syscall` by instruction pointer |
| `make clean`        | removes the four binaries and objects                                           |

**Operands:** `loop <N>`, `lat <N>`, `nop <N>`, `stream`, `stream-nop`,
`block`; `loop`, `lat` and `stream` accept `SIZE SINK MAX` for real writes.
`run_cost.sh` drives it; the header of `bench.c` describes each operand.

#### `evaluation/security/` — rows C1–C5, S1–S4

```bash
evaluation/security/run_security.sh [outdir]
```

Clean `make all`, static evidence on the four `cat` and `sig` binaries
(`analyze_binary.py`), then every dynamic case with `aon_mod` freshly loaded:
one representative run, `REPEAT` (default 100) repeats, one `strace -n -k`.
Writes `evaluation/results/<date>/` with `RESULTS.md` (`summarize.py`).
Details in [`evaluation.md`](evaluation.md#running-it).

#### `evaluation/cost/` — rows P0–P3

```bash
evaluation/cost/run_cost.sh [config]
```

Reads `cost.conf` (any key can be overridden from the environment, e.g.
`RUNS=4`), builds and runs P0 (TSC calibration and reference costs), P1/P2
(the four bench builds, per write size in `SIZES`), P3 (module unloaded vs
loaded and idle), each under batch means (`batch_means.py`), then
`analyze_cost.py` writes `COST.md` and two CSVs into
`evaluation/results/cost-<branch>-<commit>/`. Needs numpy and scipy.
Details in [`evaluation.md`](evaluation.md#cost-p0p3).

#### `evaluation/results/`

Where both scripts write their results (`<date>/` for security,
`cost-<branch>-<commit>/` for cost). Empty in this checkout; raw `*.bin` TSC
samples are never committed.

### `documentation/`

| File              | Content                                                                                                                                                        |
| ----------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `repository.md`   | this guide                                                                                                                                                     |
| `requirements.md` | platform, kernel, toolchain, Python and evaluation tools needed                                                                                                |
| `defense.md`      | how the defense works: build time, startup/teardown, run time, state, limits                                                                                   |
| `attack.md`       | vectors A and B, and the simulated vulnerabilities they use                                                                                                    |
| `evaluation.md`   | the three scenarios (`cat`, `sig`, `bench`), then the experiments: rows, how outcomes are judged, batch means, how to run each block, the `cost.conf` settings |
| `ELF-note.md`     | the `.note.aon` record: the ELF background, how it is produced and how the module reads it                                                                     |

## Adding a scenario

1. Copy `user/cat/` to `user/<name>/` and replace the victim and attacker
   sources; keep the Makefile's flags and the two `aon_syscalls` objects.
2. If the program needs a system call with no wrapper yet, add a hardened
   named wrapper to `aonlibc/aon_syscalls.S`.
3. Add the directory to `SUBDIRS` and `all` in the top-level `Makefile`, and
   its binaries to `.gitignore`.
