/*
 * cat.h - declarations for the glibc `cat` scenario of the All-or-Nothing PoC.
 *
 * ACADEMIC BASELINE. Unlike user/cat (nolibc, static, hardened library), this
 * victim is an ordinary dynamically linked glibc `cat` with no AoN mechanism
 * and no defense: it shows that, with a stock libc, both attack vectors win.
 * `execve` (nr 59) is never invoked by the victim -- only reachable by reusing
 * a `syscall`. The attacker's capabilities are SIMULATED (see attacker.S).
 */
#ifndef AON_DYNAMIC_CAT_H
#define AON_DYNAMIC_CAT_H

/* Vector A reuses an ALIGNED site: the `syscall` inside glibc's own read()
 * wrapper (resolved at runtime in cat.c, standing in for an address leak).
 * No symbol is needed here. */

/* Vector B's MISALIGNED site: an ordinary routine whose immediate operand
 * happens to contain the bytes 0f 05 (`syscall`), entered two bytes in.
 * Defined in gadget.S. */
extern long benign_compute(void);

/* Simulated attacker primitive (attacker.S): sets %rax=nr, %rdi/%rsi/%rdx=args
 * then jumps to `gadget` -- i.e. arbitrary register state + a control-flow
 * redirect onto a chosen `syscall`. */
extern void hijack(void *gadget, long nr, long a1, long a2, long a3);

#endif /* AON_DYNAMIC_CAT_H */
