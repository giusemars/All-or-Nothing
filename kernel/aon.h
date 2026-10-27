/* SPDX-License-Identifier: GPL-2.0 */
/*
 * aon.h - internal interfaces of the All-or-Nothing (AoN) kernel module.
 *
 * The module is split by responsibility:
 *
 *   aon_main.c       module init/exit: wires the pieces below together
 *   aon_lifecycle.c  exec/fork/exit hooks: discover a process's AoN region
 *                    when it execs, copy it to a forked child, forget it when
 *                    its address space dies
 *   aon_elf.c        find the AoN ELF note in a freshly exec'd address space
 *   aon_state.c      per-mm AoN region table + per-thread armed state
 *   aon_enforce.c    ingress gate (#UD fault of `ud2` -> arm), egress gate
 *                    (`syscall` -> check and disarm; any `syscall` outside
 *                    the AoN region is refused), and the signal rule
 *                    (disarm before a handler is run)
 */
#ifndef AON_H
#define AON_H

#include <linux/mm_types.h>
#include <linux/types.h>

/* The ELF note a protected program carries (emitted by
 * aonlibc/aon_syscalls.S, which duplicates these values): owner AON_NOTE_NAME,
 * type NT_AON_REGION,
 * descriptor = { s32 __start_aon_text - desc, s32 __stop_aon_text - desc }. */
#define AON_NOTE_NAME "AoN"
#define NT_AON_REGION 1

/* ---- aon_elf.c ------------------------------------------------------- */

/* Find the AoN note in @mm (== current->mm, right after exec) and return the
 * region's runtime bounds [*start, *end). Reads user memory, so may sleep.
 * Returns 0 on success, -ENOENT if the program has no AoN note, -ENOEXEC if
 * it is not an ELF image, or another negative errno on a malformed one. */
int aon_elf_find_region(struct mm_struct *mm, u64 *start, u64 *end);

/* ---- aon_state.c ----------------------------------------------------- */

int aon_region_add(struct mm_struct *mm, u64 start, u64 end);
/* Give @to the same region as @from (fork). 0 if @from has none. */
int aon_region_copy(struct mm_struct *from, struct mm_struct *to);
void aon_region_del(struct mm_struct *mm);
/* Where @ip lies for @mm: no AoN region at all (an ordinary program), or
 * outside / inside its AoN region. One lock round-trip. */
enum aon_where { AON_UNPROTECTED, AON_OUTSIDE, AON_INSIDE };
enum aon_where aon_region_where(struct mm_struct *mm, u64 ip);
bool aon_region_contains(struct mm_struct *mm, u64 ip);
bool aon_region_any(void); /* lock-free fast path: anything registered? */

void aon_armed_set(pid_t tid);
bool aon_armed_test_and_clear(pid_t tid);
void aon_armed_clear_all(void);

/* ---- aon_lifecycle.c ------------------------------------------------- */

int aon_lifecycle_init(void);
void aon_lifecycle_exit(void);

/* ---- aon_enforce.c --------------------------------------------------- */

int aon_enforce_init(void);
void aon_enforce_exit(void);

#endif /* AON_H */
