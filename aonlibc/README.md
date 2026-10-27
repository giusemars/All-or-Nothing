# `aonlibc` — the hardened syscall library

The reusable "library" half of the PoC, shared by the scenarios
([`../user_aonlibc_cat`](../user_aonlibc_cat) and
[`../user_aonlibc_signal`](../user_aonlibc_signal)). Scenarios are built on a
**vendored nolibc** whose wrappers are **hardened named wrappers**: each one is
an All-or-Nothing (AoN) block that invokes exactly the system call it is named
after.

## Contents

- [`nolibc/`](nolibc) — the vendored nolibc from Linux v6.12
  `tools/include/nolibc`, with one PoC patch: under `-DNOLIBC_AON`, `sys.h`
  declares `sys_open`, `sys_read`, `sys_write`, `sys_close`, `sys_lseek` and
  `sys_exit` **extern** instead of defining them inline, so they resolve to the wrappers
  in `aon_syscalls.S`. Without `-DNOLIBC_AON` it is ordinary nolibc.
- [`aon_syscalls.S`](aon_syscalls.S) — the hardened named wrappers, in two
  groups:
  - **file I/O + exit**: `sys_open`, `sys_read`, `sys_close`, `sys_write`,
    `sys_exit` — the intended system calls of the `cat` scenario — and
    `sys_lseek` (only the cost benchmark uses it, to rewind its sink file),
    bound to nolibc's `open()/read()/...` through `-DNOLIBC_AON`;
  - **signals**: `sys_rt_sigaction`, `sys_setitimer` and `sys_rt_sigreturn`
    (an AoN `SA_RESTORER` that executes its block again through the ingress
    gate if its `rt_sigreturn` is refused).
    They are not nolibc API: a program that installs a handler declares them
    itself (see [`../user_aonlibc_signal`](../user_aonlibc_signal)).

  One source builds two variants, selected by `-DAON_DEFEND`:
  - **baseline** (no macro): plain `mov $nr,%eax ; syscall ; ret`, no ingress
    gate and no `.note.aon` — the undefended control case;
  - **defended** (`-DAON_DEFEND`): each wrapper becomes the AoN block
    `ud2 ; mov $nr,%eax ; syscall` (ingress gate; body; `syscall` egress
    gate), followed by a `ret` outside the block. The linked blocks form the
    AoN region `[__start_aon_text,__stop_aon_text)`, described by a
    `.note.aon` descriptor the `aon_mod` kernel module reads at exec. The body
    pins the system call number only; arguments are not validated, by design.

  Each wrapper invokes the system call it is named after (`sys_open` → `open`,
  nr 2, not the `openat` upstream nolibc uses), and its `sys_*` name is a label
  on its own block (only `sys_rt_sigaction` has a `rcx → r10` marshaling stub,
  in `.text.sys_rt_sigaction`, outside the AoN region). Each block is its own
  `aon_text` input section (gas `unique,N`), so it can be included
  individually. Linked with `--gc-sections -z start-stop-gc`, only the wrappers
  of the required system calls are included, gathered into one contiguous
  output section `aon_text` whose bounds ld generates. `-z start-stop-gc` is
  **required**: without it the note's reference to `__start_/__stop_aon_text`
  keeps every block.

## How scenarios use it

There is intentionally **no Makefile here**. Each scenario's Makefile stays
self-contained and compiles these sources directly:

- `-I../aonlibc/nolibc -DNOLIBC_AON` so the victim's `open/read/write/close`
  (and the `exit` nolibc runs at `main` return) bind to `aon_syscalls.S`;
- compile `../aonlibc/aon_syscalls.S` once without `-DAON_DEFEND` (baseline
  binary) and once with it (defended binary);
- link with `-Wl,--gc-sections -Wl,-z,start-stop-gc` so only the wrappers of
  the required system calls are included.

The defended binary is then checked with the shared build tool
[`../tools/verify_aon.sh`](../tools/verify_aon.sh) (which runs
`../tools/verify_ud2`): it proves `[__start_aon_text,__stop_aon_text)` contains
no stray `ud2` besides the declared ingress gates, and that the `.note.aon`
descriptor survived `--gc-sections`.

## Scope

`execve` and every other system call without a wrapper here are deliberately
**absent**: they are not intended system calls of the scenarios, so there is
no AoN block for them. That is what makes the scenarios' reuse attacks
meaningful.

With `aon_mod` loaded, a defended program may invoke system calls **only**
through these wrappers: the module refuses any `syscall` outside the AoN region
(design property B1). So the library must cover every system call the program
invokes, including the ones nolibc's startup invokes (`exit`). nolibc features
that issue a `syscall` of their own (the generic `syscall()` macro, the stack
protector, signal restorers) would be refused at run time, and so would a call
into the vDSO.
