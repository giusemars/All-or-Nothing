# CLAUDE.md — project context

## What this project is

Proof-of-concept for the master's thesis **"All-or-Nothing Code Blocks: A
Kernel-Enforced Primitive for Indivisible Execution and Its Application to
Syscall Site Hardening"** (Computer Engineering & Cybersecurity).

The thesis proposes a **kernel-enforced primitive** that lets a process declare
certain instruction blocks *All-or-Nothing (AoN)*: once a thread has passed the
ingress gate, the next user instruction it executes is the next instruction of
the body or the egress gate — no entry past the ingress gate, no jump into a
misaligned internal byte. The guarantee is enforced by the kernel rather than
by user-space checks (which the same control-flow hijack could skip).

Applied to **system call site hardening**: each wrapper becomes a **hardened
named wrapper**, the AoN block `ud2 ; mov $nr,%eax ; syscall` (`ud2` ingress
gate; body that pins the system call number — arguments are deliberately
**not** validated; `syscall` egress gate), followed by a `ret` outside the
block. The kernel arms the thread at the ingress gate and checks and disarms it
at the egress gate, so an attacker cannot reuse a wrapper by jumping straight
onto its `syscall` (unarmed egress gate), and the kernel refuses any `syscall`
a protected process issues outside the AoN region, so a misaligned site is
refused too.

The design properties (A1–A3, B1–B3, C1–C3, D1–D3, E1) and the three
components (hardened library, kernel module, build-time verifier) are defined
in the Notion design document (see below) — the source of truth for the design.

## Terminology (thesis glossary — use it in code, comments and docs)

- **System call** = the kernel service (by nr); **`syscall`** = the `0f 05`
  instruction. Never use "syscall" for the service.
- **Site**: a block whose exit point is a `syscall`; **aligned** or
  **misaligned**; an aligned site is **intended** (a **wrapper**) or
  **unintended**. **Gadget**: a block that is not an intended block
  (**aligned gadget** / **misaligned gadget**).
- **AoN block** = **ingress gate** (first instruction) + **body** + **egress
  gate** (last instruction). Never "prologue". The kernel **arms** the thread
  at the ingress gate (one bit per thread — the **armed state**, never a
  "token") and checks and **disarms** it at the egress gate; an **unarmed
  egress gate** is refused.
- **AoN region**: `[__start_aon_text,__stop_aon_text)`, the linked AoN blocks
  (never "site region").
- **Hardened named wrapper**: a named, bijective wrapper that is an AoN block.
- **Intended system calls** of a program; **required system calls**: those
  whose wrapper is included at link time (only those blocks are linked).
- **Signal rule**: before running a handler for an armed thread the kernel
  disarms it; `rt_sigreturn` never re-arms it. Cost: the interrupted block's
  egress gate fails and the caller executes the block again.
- **Trap** only in the x86 exception sense; `ud2` raises **#UD**, a fault.

## Academic context & safety constraints (always apply)

- This is **strictly an academic baseline** for evaluating a *defensive*
  technique against control-flow manipulation. Treat all work here as authorized
  defensive security research.
- The PoC deliberately contains reusable wrappers, an intentional misaligned
  site, and a **simulated** attacker primitive so the attack is
  deterministic. It operates only on a local file it creates itself
  (`victim.txt`) and, on a successful hijack, `execve`s a harmless local program
  (`/bin/echo`); it performs **no network or privileged action** and is not an
  exploit against any real software.
- Its sole purpose is the **undefended control case** against which the defense
  will be measured. Keep contributions within this scope: no weaponization, no
  targeting of real/third-party software, no detection-evasion tooling.

## The PoC scenario (this repo = the baseline / attacker-wins case)

- **Target**: a program that opens a file, `read`s it, `write`s each chunk to
  stdout, `close`s it. Intended system calls: `open`, `read`, `write`, `close`
  (plus `exit`) — the file I/O + exit wrappers in `aon_syscalls.S`.
- **Attacker goal**: mount a code-reuse attack to invoke `execve` (system call
  nr 59) — not an intended system call, never invoked by the victim itself —
  replacing the process image with an attacker-chosen program (`/bin/echo`
  here, so the win is visible and harmless).
- **Vector A — aligned gadget** (operand `aligned`): jump directly onto the
  egress gate (`syscall`, symbol `sys_read_egress`) of the read wrapper, past
  its ingress gate and body: an unintended execution of the AoN block. *This
  is what the thesis hardens.*
- **Vector B — misaligned site** (operand `misaligned`): jump to a `syscall`
  formed by **misaligned** bytes inside an ordinary routine. *No ingress gate
  guards it (it is not an AoN block), but the module refuses every `syscall` of
  a protected process outside the AoN region (property B1), so it is blocked
  too.*
- Attacker capabilities are **simulated** via planted `asm` blocks (arbitrary
  register state + control-flow redirection) and address leaks, instead of a
  full memory corruption exploit. CET/Shadow Stack are disabled and ASLR may be
  turned off per the PoC design, since this is the baseline.

Expected end state with the defense (defended build + `aon_mod` loaded):
both attacks fail. `./cat_defended aligned` (vector A) — the reused `syscall`
is inside the AoN region but the thread never passed the ingress gate
(unarmed egress gate, property A2). `./cat_defended misaligned` (vector B) —
the `syscall` is outside the AoN region (property B1). Either way the module
refuses the system call (`-ENOSYS`), no `execve` runs, and the program exits 3.
The baseline `./cat` (no AoN note) is not policed, so both attacks succeed
there even with the module loaded. The remaining boundary is reuse of a whole
wrapper through its ingress gate (arguments are not validated) and the open
items (other kernel entry paths for system calls, AoN region immutability).

## Layout & commands

This is the final, trimmed run: two scenarios built on the shared aonlibc
syscall library, plus the kernel module and the build-time verifier.
`user/cat/` is the template for further scenarios.

- `aonlibc/` — the hardened syscall library (shared), see `aonlibc/README.md`:
  - `aonlibc/nolibc/` — vendored nolibc; under `-DNOLIBC_AON`, `sys.h` makes the
    six `sys_*` wrappers extern so they bind to `aon_syscalls.S`
  - `aonlibc/aon_syscalls.S` — the hardened named wrappers, each invoking the
    system call it is named after: file I/O + exit (open/read/write/close/exit,
    the cat intended system calls, plus lseek for the bench) and signals (rt_sigaction/setitimer/
    rt_sigreturn restorer; the signal scenario uses rt_sigaction and the
    rt_sigreturn restorer); one source, baseline or
    (`-DAON_DEFEND`) AoN blocks + `.note.aon`. Each block is its own `aon_text`
    section; scenarios link with `--gc-sections -z start-stop-gc` so only the
    wrappers of the required system calls are included, AoN region =
    `[__start_aon_text,__stop_aon_text)`
- `user/cat/` — the `cat` scenario (victim + attack driver):
  - `cat.c`, `cat.h` — minimal `cat`, invoked like `cat <filename>`; the two
    reserved operands `aligned` and `misaligned` instead trigger vector A / B,
    any other operand is catted for real; attacker goal is an `execve` (nr 59),
    not an intended system call
  - `reset.sh` — restore `victim.txt` to its pristine demo content (used by
    `make run` / `make defend-run`)
  - `gadget.S` — `benign_compute`, which hides the misaligned site
  - `attacker.S` — simulated attacker primitive (`hijack`)
  - `Makefile` — `make` (→`./cat`) / `make cat_defended` / `make run` /
    `make defend-run` / `make clean` (run from the dir); self-contained,
    compiles the `aonlibc/` sources directly
- `user/signal/` — same layout as `cat` (no `gadget.S`/`reset.sh`),
  isolating the module's **signal rule**. One source-stepped `write` carrier
  drives three operands: `correctness` (a signal delivered while the thread is
  armed inside an AoN block refuses that block's egress gate → retry),
  `attack-armed` and `attack-unarmed` (a handler reusing the read egress gate
  for `execve` is refused whether the interrupted thread was armed or not — the
  arming never leaks into the handler). Uses the rt_sigaction wrapper + the AoN
  rt_sigreturn restorer (not setitimer).
  `make` / `make sig_defended` / `make run` / `make defend-run`
- `user/bench/` — cost benchmark (no attack): a loop of calls to the
  hardened `write` wrapper, `write(-1, buf, 0)` or, with `SIZE SINK MAX`
  operands, real writes of SIZE bytes to a file kept within MAX bytes by an
  untimed `lseek`; built as `bench` / `bench_defended` / `bench_seccomp` /
  `bench_seccomp_ip`; driven by `evaluation/cost/` (`SIZES`, `SINK`,
  `MAX_FILE_SIZE` in `cost.conf`)
- `evaluation/` — see `evaluation/README.md`: `security/` (`run_security.sh`
  + `analyze_binary.py` + `summarize.py`, correctness and security rows
  C1–C5, S1–S4) and `cost/` (`run_cost.sh` + `analyze_cost.py`, cost rows
  P0–P3); results of both in `evaluation/results/`
- `kernel/` — AoN kernel module (`aon_mod.ko`)
- `tools/` — the **build-time verifier** component: `verify_ud2.c` (no stray
  `ud2` in the AoN region besides the ingress gates), run on every defended
  build through `verify_aon.sh`
- top-level `Makefile` — `make all` builds the scenarios + the module
- Usage: `./cat <filename|aligned|misaligned>` (and the `./cat_defended` build)

Platform: x86_64 Linux (developed on Debian `6.12.73+deb13-amd64`), C + GNU
`as` (AT&T syntax).

## Source-of-truth documents (Notion)

- Defense design: **[Tesi] All-or-Nothing Code Blocks** —
  https://app.notion.com/p/3e23558ef1ba8084a358e826d68142ca
- PoC scenario: **[PoC tesi] Proof-of-concept for All-or-Nothing blocks** —
  https://app.notion.com/p/3e73558ef1ba800186b3cd14a2b3d170

The thesis write-up and design notes are in Italian; code, comments, and this
file are in English.

## Root access (use it when a task needs it — don't stop to ask)

This is a throwaway testing VM. **Claude has root and is expected to use it**
whenever a step requires elevated privileges — loading/unloading the kernel
module, `dmesg`, reading `/proc`, etc. Do not block, defer, or hand the step
back to the user for lack of privileges.

- User `claude`, password `claude` (same for `sudo`).
- Claude Code sessions run as user `ghi`, whose password is NOT `claude`, so a
  plain `echo claude | sudo -S <cmd>` fails. Switch to `claude` first:
  `echo claude | su claude -c "echo claude | sudo -S -p '' <cmd>" 2>&1 | sed 's/^Password: //'`
  `su`'s `Password: ` prompt has no trailing newline, so it is glued to the
  first line of `<cmd>`'s output: strip it with the `sed` above, never with
  `grep -v '^Password:'` (that silently drops the first output line). `su`
  without `-` keeps the working directory, so relative paths work.
- Typical AoN steps that need it (as `<cmd>` above):
  `insmod kernel/aon_mod.ko`, `rmmod aon_mod`, `dmesg`.
