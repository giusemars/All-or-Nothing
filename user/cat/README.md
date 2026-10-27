# `user/cat` — aonlibc `cat`, execve-reuse scenario

An **academic baseline** scenario for *All-or-Nothing Code Blocks*, and the
**self-contained basis** for further scenarios: every source it needs lives in
this directory, so the other `user*` dirs can be removed without breaking it.
It has two parts:

- an **aonlibc** victim: `-nostdlib -static`, linked against the vendored
  [`../../aonlibc/nolibc/`](../../aonlibc/nolibc), whose wrappers are the hardened
  named wrappers (AoN blocks) in
  [`../../aonlibc/aon_syscalls.S`](../../aonlibc/aon_syscalls.S);
- a three-mode **attack methodology** — `<filename>` / `aligned` /
  `misaligned` — with the simulated attacker primitives in
  [`gadget.S`](gadget.S) and [`attacker.S`](attacker.S).

The only thing it uses from outside is the shared, scenario-independent build
tool [`../../tools/verify_aon.py`](../../tools/verify_aon.py) and, at run time, the
`aon_mod` kernel module in [`../../kernel`](../../kernel) — neither of which is a
`user*` dir.

## Victim

A minimal `cat`: `open(victim.txt)` → `read` loop → `write(stdout)` → `close`.
Its **intended system calls** are exactly those of its five wrappers: `open`,
`read`, `write`, `close`, `exit`.

## Attacker goal: `execve` (nr 59) — not an intended system call

The victim never invokes `execve`, and no wrapper exists for it. The only way
to invoke it is by **reusing** a `syscall` instruction:

| mode         | gadget                                        | vector | blocked in the defended build by |
|--------------|-----------------------------------------------|--------|------------|
| `<filename>` | — (runs the real cat)                         | —      | —          |
| `aligned`    | aligned gadget: the egress gate of the read wrapper (`sys_read_egress`), with `%rax=59` | **A**  | A2: unarmed egress gate (the thread never passed the ingress gate) |
| `misaligned` | misaligned site at `benign_compute+2`, with `%rax=59` | **B**  | B1: `syscall` outside the AoN region |

A successful hijack replaces the process image with `/bin/echo` (harmless and
visible); a blocked one leaves the process intact.

## Two builds from one source

`aon_syscalls.S` builds both variants, selected by `-DAON_DEFEND`:

- **`cat`** (baseline): wrappers are plain `mov/syscall/ret`, no ingress gate,
  no `.note.aon`. aon_mod does not intervene — the attacker-wins control case.
- **`cat_defended`**: each wrapper becomes an AoN block with a `ud2` ingress
  gate, and the linked blocks form the AoN region
  `[__start_aon_text,__stop_aon_text)`, described by a `.note.aon` descriptor
  aon_mod reads at exec. The build then runs
  [`../../tools/verify_aon.py`](../../tools/verify_aon.py) to prove the AoN region contains no stray
  `ud2` besides the declared ingress gates, and checks the note survived
  `--gc-sections`.

`cat.c` is compiled with `-DNOLIBC_AON` in **both** builds, so `nolibc/sys.h`
declares the five `sys_*` wrappers `extern` and they resolve to
`aon_syscalls.S`. This gives a stable egress gate symbol (`sys_read_egress`)
for the attack in the baseline too, so the attack driver is identical across
builds.

## Commands

```bash
make                 # build ./cat (baseline)
make run             # seed victim.txt, run all baseline modes
make cat_defended    # build ./cat_defended, then verify its AoN region
make defend-run      # seed victim.txt, run all defended modes
make clean
```

`defend-run` needs `aon_mod` loaded (`cd ../../kernel && make load`); without it
the `ud2` ingress gates raise #UD, delivered as `SIGILL`.

## Expected results

| mode         | `./cat` (baseline)        | `./cat_defended` (module loaded)             |
|--------------|---------------------------|----------------------------------------------|
| `victim.txt` | prints the file, exit 0   | prints the file, exit 0                      |
| `aligned`    | execve → `/bin/echo` runs | **blocked** (unarmed egress gate): aon_mod refuses the system call (default: nr → `-ENOSYS`); no execve, exit 3 |
| `misaligned` | execve → `/bin/echo` runs | **blocked** (outside the AoN region): no execve, exit 3 |

This is the thesis end-state: both vectors are blocked. `dmesg` shows one line
per blocked attempt, e.g.
`aon: BLOCKED system call nr=59 at syscall 0x4015a5 (unarmed egress gate)` and
`aon: BLOCKED system call nr=59 at syscall 0x401579 (outside the AoN region)`.
