# The attacks: vectors A and B

## Background

The victim is `cat` ([`user/cat/`](../user/cat/README.md)): it opens a file,
`read`s it, `write`s it to stdout and `close`s it. Its **intended system
calls** are `open`, `read`, `write`, `close` and `exit`, each made through its
hardened named wrapper.

The attacker wants **`execve`** (nr 59), to replace the process with a program
of their choice. `cat` never invokes `execve` and has no wrapper for it, so
the only way to get it is **code reuse**: put 59 in `%rax`, the arguments in
`%rdi`/`%rsi`/`%rdx`, and jump to a `syscall` instruction already in the
binary. There are two kinds of such instruction, and so two vectors:

| Vector | Target | Kind of site | Refused on the defended build because |
| --- | --- | --- | --- |
| **A** | the `syscall` of the read wrapper (`sys_read_egress`) | aligned gadget: an intended block entered in the middle | the thread never passed the ingress gate: **unarmed egress gate** (A2) |
| **B** | a `0f 05` hidden inside an instruction of `benign_compute` | misaligned site: a `syscall` nobody wrote | the `syscall` is **outside the AoN region** (B1) |

The attacker's program here is `/bin/echo`, which prints
`[attacker] execve() hijack succeeded -- process image replaced`. That makes a
win visible and keeps it harmless.

## The artificial vulnerabilities

A real attack needs a memory-corruption bug and information leaks. The PoC
**simulates** them so the attack is deterministic and identical on both
builds. Three pieces stand in for the bug:

| Piece | File | Stands in for |
| --- | --- | --- |
| `hijack` | [`user/cat/attacker.S`](../user/cat/attacker.S) | the bug itself: arbitrary register state + control-flow redirection |
| `sys_read_egress` | [`aonlibc/aon_syscalls.S`](../aonlibc/aon_syscalls.S) | an address leak of the read wrapper's `syscall` |
| `benign_compute` | [`user/cat/gadget.S`](../user/cat/gadget.S) | an unlucky routine whose bytes contain `0f 05` |

All three exist in both builds, and `cat.c` calls them the same way. The only
difference between `cat` and `cat_defended` is the wrappers.

### `hijack`: the corruption primitive

```
void hijack(void *gadget, long nr, long a1, long a2, long a3)

hijack:
    movq  %rdi, %r11      # r11 = target `syscall`
    movq  %rsi, %rax      # rax = system call nr
    movq  %rdx, %rdi      # arg1: path
    movq  %rcx, %rsi      # arg2: argv
    movq  %r8,  %rdx      # arg3: envp
    jmp   *%r11           # redirect control flow onto the target
```

It models the two capabilities of the threat model: **set any register** and
**jump to any address**. In a real exploit these would come from, e.g., an
overwritten return address and a ROP chain. `hijack` is entered with `call`
and leaves with a `jmp`, so the `ret` after the target `syscall` pops the
return address of `call hijack`. If the `execve` does not happen, control
returns cleanly to `main`, which reports the attack blocked and exits 3.

### The address leak

The binaries are static and `-no-pie`, so every address is fixed at link
time. `cat.c` takes the targets straight from symbols, as if the attacker had
leaked them:

- `sys_read_egress`, a label the library puts on the read wrapper's
  `syscall` in **both** builds, so vector A aims at the same instruction
  either way;
- `benign_compute + 2`, the misaligned `0f 05`.

## Vector A: aligned gadget

The read wrapper on the two builds:

```
baseline (cat)                     defended (cat_defended)
sys_read:                          __aon_read / sys_read:
                                       ud2               # ingress gate
    mov   $0, %eax                     mov   $0, %eax    # body
sys_read_egress:                   sys_read_egress:
    syscall                            syscall           # egress gate
    ret                                ret
```

`./cat aligned` runs:

```c
hijack(sys_read_egress, 59, "/bin/echo", EVIL_ARGV, EVIL_ENVP);
```

The jump skips the `mov $0,%eax` that would pin the number to `read`, so the
`syscall` runs with `%rax = 59`.

- **Baseline**: nothing checks how the `syscall` was reached. `execve` runs
  and `/bin/echo` replaces the process.
- **Defended**: the thread skipped the `ud2`, so the kernel never armed it.
  At the egress gate `aon_mod` finds an unarmed thread and refuses the call
  (by default it rewrites the number, so the call returns `-ENOSYS`). The
  wrapper's `ret` returns to `main`, which exits 3. The kernel log shows
  `aon: BLOCKED system call nr=59 ... (unarmed egress gate)`.

This is the attack the thesis hardens. The block's body pins the number, and
the ingress gate makes the body impossible to skip.

## Vector B: misaligned site

`benign_compute` is an ordinary routine. Its immediate operand happens to
contain the bytes `0f 05 c3`:

```
benign_compute:
  401562:  48 b8 0f 05 c3 90 90 90 90 90   movabs $0x9090909090c3050f,%rax
  40156c:  c3                              ret
```

Decoded from its start, it is a harmless `movabs` and a `ret`. Decoded from
`benign_compute + 2`, the same bytes read:

```
  401564:  0f 05     syscall
  401566:  c3        ret
```

`./cat misaligned` runs:

```c
hijack(benign_compute + 2, 59, "/bin/echo", EVIL_ARGV, EVIL_ENVP);
```

- **Baseline**: the misaligned `syscall` runs `execve` and `/bin/echo`
  replaces the process.
- **Defended**: `benign_compute` is application code, not part of the
  library, so it lies outside the AoN region. No ingress gate guards it,
  because it is not a block at all. `aon_mod` refuses every `syscall` a
  protected process issues outside the AoN region, so it is refused anyway.
  The hidden `ret` (`c3`) returns to `main`, which exits 3. The kernel log
  shows `aon: BLOCKED system call nr=59 ... (outside the AoN region)`.

Here the misaligned site is planted on purpose. The evaluation also found an
unplanted one in `sig` (the immediate of a `cmp $0x50f,%ax` the compiler
emitted for ordinary C code): such sites happen without anyone writing them.
It is refused for the same reason.

## Running it

```bash
make -C user/cat run
```

```bash
make -C user/cat defend-run
```

The second needs `aon_mod` loaded. Expected results:

| Command | Baseline `./cat` | Defended `./cat_defended` + `aon_mod` |
| --- | --- | --- |
| `victim.txt` | prints the file, exit 0 | prints the file, exit 0 |
| `aligned` | `[attacker] execve() hijack succeeded ...` | refused (unarmed egress gate), exit 3 |
| `misaligned` | `[attacker] execve() hijack succeeded ...` | refused (outside the AoN region), exit 3 |

These are rows S1 and S2 of the evaluation ([`evaluation.md`](evaluation.md)).

## The same attack from a signal handler

[`user/signal/`](../user/signal/README.md) repeats vector A from inside a
signal handler. It uses the same `hijack` and the same `sys_read_egress`
target, and checks that the arming of an interrupted thread never leaks into
the handler:

- `attack-unarmed`: the handler interrupted ordinary code;
- `attack-armed`: the handler interrupted a thread armed inside `write`.

Both are refused (rows S3 and S4).

## What the attacks do not show

- **Whole-wrapper reuse.** An attacker who calls a wrapper from its ingress
  gate with their own arguments is not stopped: arguments are not validated
  by design. They are limited to the program's required system calls,
  though, and `execve` is not one of them.
- **A real exploit.** The bug, the leak and the gadget are planted. The
  attacks show what the module does with a hijacked thread, not that a real
  corruption reaches that state.
