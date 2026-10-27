# `user/signal` — the signal rule, both sides

A focused scenario for `aon_mod`'s **signal rule** — the kprobe on
`x64_setup_rt_frame` that **disarms the thread before a handler is run**, and
the AoN `rt_sigreturn` restorer that **never re-arms it**. Where the `cat`
scenario shows the two reuse vectors blocked on the main thread, this one shows
what the signal rule buys and what it costs, in three reserved operands:

| operand | shows | side |
|---------|-------|------|
| `correctness` | a signal delivered while the thread is **armed** inside an AoN block refuses that block's egress gate; the caller executes the block again | availability |
| `attack-armed` | a handler invoked **while the thread is armed inside a block** cannot ride that live arming into a reused `syscall`: the arming does not leak across the handler boundary | security |
| `attack-unarmed` | a handler invoked **while the thread is in ordinary code** (never armed) also cannot: a handler has no arming to begin with | security |

All three modes use **one mechanism** — single-stepping (`EFLAGS.TF`) a
protected `write` so a `SIGTRAP` is delivered to the thread. They differ only in
*when* the handler fires and what it does there: the first trap, in ordinary
code (`attack-unarmed`), or the trap on the block's egress gate while armed
(`correctness` and `attack-armed`); and once there, nothing (`correctness`) or
the hijack (`attack-*`).

Self-contained like the other scenarios — every source it needs is here, plus
the shared library ([`../../aonlibc`](../../aonlibc)) and the build tool
([`../../tools/verify_aon.py`](../../tools/verify_aon.py)). The only local attacker
primitive is the simulated `hijack` ([`attacker.S`](attacker.S)); there is no
misaligned-site gadget (vector B is the `cat` scenario's job).

## `correctness` — a signal while armed refuses the egress

The program single-steps a protected `write`. With `EFLAGS.TF` set, the CPU
raises `#DB` (delivered as `SIGTRAP`) after each instruction, so a `SIGTRAP` is
guaranteed to land **while the thread is armed inside the write block**. The
`SIGTRAP` handler stops stepping the moment RIP sits on the block's `syscall`
(its egress gate). By then the kernel has already **disarmed** the thread, so
when the thread resumes onto the `syscall` it is an **unarmed egress gate** and
is refused with `-ENOSYS`. The program simply runs the block again:

```
write #1 = -38  (-ENOSYS: egress refused -- a signal ran while the thread was armed)
write #2 = 38   (the block was executed again -- recovered)
```

This is the availability cost of the rule, made deterministic: no timing races,
exactly one refusal and one retry.

> A real program that invokes all of its system calls through the library must
> wrap each call on a signal-reachable path in an `-ENOSYS` retry loop for the
> same reason: under a real signal load (e.g. a periodic timer) the refusals
> happen statistically rather than once. This scenario pins the single
> mechanism behind that cost down to one deterministic event.

## `attack-*` — a handler cannot invoke the reused `syscall`, either way

In both cases the attacker's handler reuses the read wrapper's egress gate
(`sys_read_egress`) with `%rax = 59` to invoke `execve` (**not** an intended
system call of this program). The two cases differ in what the interrupted
thread was doing when the handler fired — the two possibilities an attacker
could try.

**`attack-unarmed` (the basic case).** The handler fires on the first
single-step trap, while the thread is in ordinary code, outside any AoN block —
so it is not armed. The reused `syscall` is an unarmed egress gate and is
refused. A handler simply has no arming to spend.

**`attack-armed` (the stronger case).** The handler is instead driven onto the
`write` block's egress gate, so it fires **while the thread is legitimately
armed**, mid-wrapper. This is the case that could actually matter: if the
thread's arming carried into the handler, the reused egress gate would be armed
and the `execve` would run. It does not — the kernel **disarms the thread before
running the handler**, and `rt_sigreturn` never re-arms it — so a control-flow
hijack cannot be *timed* to catch the victim mid-wrapper and inherit its arming.

Together they make the full statement: **no matter what the interrupted thread
was doing, a handler reaches a reused `syscall` unarmed, so it is refused.** On
the defended build `dmesg` shows the difference between the two:

- `attack-unarmed`: a single `BLOCKED … nr=59 … (unarmed egress gate)`, with
  **no `DISARMED`** line — the thread was never armed.
- `attack-armed`: a `DISARMED` at the armed `write` egress, then the handler's
  `execve` (`nr=59`) `BLOCKED` at the *read* egress, then the interrupted carrier
  `write` (`nr=1`) `BLOCKED` as it resumes disarmed.

## Two builds from one source

`aon_syscalls.S` builds both variants, selected by `-DAON_DEFEND`:

- **`sig`** (baseline): plain `mov/syscall/ret`, no ingress gate, no
  `.note.aon` — `aon_mod` does not intervene. Both `attack-*` run the `execve`
  (`/bin/echo` replaces the process, attacker wins); `correctness` has no
  arming to lose, so the first write simply succeeds and the demo reports *not
  demonstrated*.
- **`sig_defended`**: each wrapper becomes an AoN block with a `ud2` ingress
  gate, and the linked blocks form the AoN region
  `[__start_aon_text,__stop_aon_text)` (**5 ingress gates**: `read` — kept
  only because the `attack-*` modes reuse its egress gate — plus `write`,
  `exit`, `rt_sigaction`, `rt_sigreturn`), described by a `.note.aon`
  descriptor. The build runs
  [`../../tools/verify_aon.py`](../../tools/verify_aon.py) and checks the note
  survived `--gc-sections`.

`sig.c` never calls `read()`; the read block stays linked only because `sig.c`
references `sys_read_egress`.

## Commands

```bash
make                # build ./sig (baseline)
make run            # run all baseline modes
make sig_defended   # build ./sig_defended, then verify its AoN region
make defend-run     # run all defended modes
make clean
```

`defend-run` needs `aon_mod` loaded (`cd ../../kernel && make load`); without it
the `ud2` ingress gates raise `#UD`, delivered as `SIGILL`.

## Expected results

| mode | `./sig` (baseline) | `./sig_defended` (module loaded) |
|------|--------------------|----------------------------------|
| `correctness` | write #1 allowed; *not demonstrated* (no arming) | write #1 refused (`-ENOSYS`), write #2 recovers; exit 0 |
| `attack-armed` | `execve` → `/bin/echo` runs (attacker wins) | **blocked**: arming disarmed before the handler, unarmed egress gate, exit 3 |
| `attack-unarmed` | `execve` → `/bin/echo` runs (attacker wins) | **blocked**: handler never armed, unarmed egress gate, exit 3 |

On the defended build, `dmesg` shows the kernel events behind each outcome:

```
# correctness: SIGTRAP lands on the armed write egress -> disarm -> the write is refused
aon: DISARMED at signal 5 delivery, interrupted at 0x…  (x64_setup_rt_frame)
aon: BLOCKED system call nr=1 at syscall 0x… (unarmed egress gate)

# attack-armed: same disarm, then the handler's reused read egress (execve) is refused,
#               then the interrupted carrier write is refused as it resumes disarmed
aon: DISARMED at signal 5 delivery, interrupted at 0x…A (x64_setup_rt_frame)
aon: BLOCKED system call nr=59 at syscall 0x…B (unarmed egress gate)
aon: BLOCKED system call nr=1  at syscall 0x…A (unarmed egress gate)

# attack-unarmed: the handler fired in ordinary code, so NO disarm -- just the refusal
aon: BLOCKED system call nr=59 at syscall 0x…B (unarmed egress gate)
```

(`signal 5` = `SIGTRAP`; `nr=1` = `write`; `nr=59` = `execve`. `0x…A` is the
write egress the thread was armed on; `0x…B` is the read egress the handler
reused — a *different* gate, refused because the arming did not follow the
thread into the handler. The missing `DISARMED` in the unarmed case is the
tell: there was no arming to spend.)
