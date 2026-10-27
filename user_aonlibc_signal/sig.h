/*
 * sig.h - declarations for the aonlibc `signal` scenario of the All-or-Nothing
 * Code Blocks PoC.
 *
 * This scenario isolates the one part of the design that is specific to
 * signals: aon_mod's SIGNAL RULE (the kprobe on x64_setup_rt_frame -- disarm
 * the thread before a handler is run; rt_sigreturn never re-arms it). It makes
 * its points through three reserved operands -- one availability, two
 * security:
 *
 *   correctness  a signal delivered to a thread that is ARMED inside an AoN
 *                block gets that block's egress gate REFUSED. The caller must
 *                execute the block again. This is the availability cost of the
 *                rule, shown deterministically by single-stepping a protected
 *                `write` so a SIGTRAP lands on the armed egress gate.
 *
 *   attack-armed   a handler CANNOT ride a live arming into a reused system
 *                call. It is invoked while the thread is armed inside an AoN
 *                block (a `write` single-stepped so the handler fires on its
 *                egress gate) and from there reuses the read wrapper's egress
 *                gate for execve. The kernel disarms before running the handler
 *                and rt_sigreturn never re-arms, so the victim's live arming is
 *                not available to the handler: the reused egress gate is
 *                unarmed and is refused.
 *
 *   attack-unarmed  the same hijack from a handler invoked while the thread is
 *                in ordinary code (not in any AoN block, so never armed). A
 *                handler is never armed to begin with, so the reused egress
 *                gate is unarmed and is refused. The basic case; attack-armed
 *                is the stronger one.
 *
 * As in the other scenarios the attacker's capabilities are SIMULATED (see
 * attacker.S); the goal is an `execve` (nr 59), not an intended system call of
 * this program.
 */
#ifndef AONLIBC_SIG_H
#define AONLIBC_SIG_H

/* ---- Egress gate of the read wrapper (the reused gadget) ---------------
 * The `syscall` instruction of the read AoN block in
 * ../aonlibc/aon_syscalls.S, past the `ud2` ingress gate and the body. The
 * attacker is assumed to have leaked this address; the `attack-*` operands jump
 * onto it with %rax forced to 59 (execve) from inside a signal handler.
 * Exported in both builds, so the attack driver is identical across them. This
 * reference is also what keeps the read block linked into this program, whose
 * own code never calls read(). */
extern char sys_read_egress[];

/* ---- Simulated attacker primitive --------------------------------------
 * Stands in for a memory corruption vulnerability giving the attacker (a) an
 * arbitrary register state and (b) the ability to redirect control flow to an
 * arbitrary address (here, a `syscall` instruction). Defined in attacker.S.
 *
 *   void hijack(void *gadget, long nr, long a1, long a2, long a3)
 * loads %rax=nr, %rdi=a1, %rsi=a2, %rdx=a3, then jumps to `gadget`; the `ret`
 * that follows the reused `syscall` returns to hijack's caller. In this
 * scenario hijack is called from within a signal handler. */
extern void hijack(void *gadget, long nr, long a1, long a2, long a3);

#endif /* AONLIBC_SIG_H */
