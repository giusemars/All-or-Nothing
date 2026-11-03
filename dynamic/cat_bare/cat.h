/*
 * cat.h - declarations for the "bare syscall" glibc `cat` scenario of the
 * All-or-Nothing PoC.
 *
 * ACADEMIC BASELINE. Like the sibling `cat` scenario this is an ordinary
 * dynamically linked glibc program with no AoN mechanism and no defense, but
 * its file-I/O system calls are issued by the program's own bare `syscall`
 * wrappers (syscalls.S) instead of glibc's. It shows that moving the
 * `syscall` instructions into the program binary does not, on its own, defend
 * anything: both attack vectors still win.
 *
 * `execve` (nr 59) is never invoked by the victim -- only reachable by reusing
 * a `syscall`. The attacker's capabilities are SIMULATED (see attacker.S).
 */
#ifndef AON_DYNAMIC_CAT_BARE_H
#define AON_DYNAMIC_CAT_BARE_H

/* Bare direct-system-call wrappers (syscalls.S): each pins its system call
 * number and runs the `syscall` instruction in the program's own .text. */
extern long raw_open(const char *path, int flags, int mode);
extern long raw_read(int fd, void *buf, unsigned long count);
extern long raw_write(int fd, const void *buf, unsigned long count);
extern long raw_close(int fd);

/* Vector A reuses an ALIGNED site: here the `syscall` inside the program's own
 * raw_read wrapper (resolved at runtime in cat.c, standing in for an address
 * leak) -- in the sibling scenario it was glibc's read() wrapper instead. */

/* Vector B's MISALIGNED site: an ordinary routine whose immediate operand
 * happens to contain the bytes 0f 05 (`syscall`), entered two bytes in.
 * Defined in gadget.S. */
extern long benign_compute(void);

/* Simulated attacker primitive (attacker.S): sets %rax=nr, %rdi/%rsi/%rdx=args
 * then jumps to `gadget` -- i.e. arbitrary register state + a control-flow
 * redirect onto a chosen `syscall`. */
extern void hijack(void *gadget, long nr, long a1, long a2, long a3);

#endif /* AON_DYNAMIC_CAT_BARE_H */
