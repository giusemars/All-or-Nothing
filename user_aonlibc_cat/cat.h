/*
 * cat.h - declarations for the aonlibc `cat` scenario of the All-or-Nothing
 * Code Blocks PoC.
 *
 * ACADEMIC BASELINE. The victim is a minimal `cat`: open a file, read it in a
 * loop, write each chunk to stdout, close. All of its I/O goes through the
 * hardened named wrappers in ../aonlibc/aon_syscalls.S (open / read / write /
 * close / exit) -- its INTENDED system calls. `execve` (nr 59) is deliberately
 * NOT one of them and the victim never invokes it; the only way to invoke it
 * is by reusing a `syscall` instruction, which is what the thesis is about.
 *
 * The attacker's capabilities are SIMULATED (see attacker.S): this is the
 * undefended control case, not a real exploit.
 */
#ifndef AONLIBC_CAT_H
#define AONLIBC_CAT_H

/* ---- Egress gate of the read wrapper (vector A) ------------------------
 * The `syscall` instruction of the read AoN block in
 * ../aonlibc/aon_syscalls.S, past the `ud2` ingress gate and the
 * `mov $0,%eax` body. The attacker is assumed to have leaked this address.
 * Jumping onto it with %rax forced to 59 executes an aligned gadget (an
 * unintended execution of the read block) that invokes execve -- the attack
 * the thesis hardens (vector A). Exported by the library in BOTH the baseline
 * and the defended build, so the attack driver is identical across them. */
extern char sys_read_egress[];

/* ---- Misaligned site (vector B) ----------------------------------------
 * An ordinary victim routine whose machine code accidentally contains the
 * bytes 0f 05 (`syscall`) inside an immediate operand. Entered two bytes in,
 * it decodes as a misaligned site that lies OUTSIDE the AoN region. It is not
 * an AoN block, so no ingress gate guards it; it is blocked instead because
 * aon_mod refuses every `syscall` of a protected process outside the AoN
 * region (design property B1). Defined in gadget.S. */
extern long benign_compute(void);

/* ---- Simulated attacker primitive --------------------------------------
 * Stands in for a memory corruption vulnerability giving the attacker (a) an
 * arbitrary register state and (b) the ability to redirect control flow to an
 * arbitrary address (here, a `syscall` instruction). Defined in attacker.S.
 *
 *   void hijack(void *gadget, long nr, long a1, long a2, long a3)
 * loads %rax=nr, %rdi=a1, %rsi=a2, %rdx=a3, then jumps to `gadget`. */
extern void hijack(void *gadget, long nr, long a1, long a2, long a3);

#endif /* AONLIBC_CAT_H */
