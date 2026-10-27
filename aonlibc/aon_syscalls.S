/*
 * aon_syscalls.S - the hardened named wrappers of aonlibc (x86_64, AT&T
 * syntax). Each wrapper is an AoN block that invokes exactly the system call
 * it is named after, and it is the only wrapper that can invoke it (bijective).
 * Two groups:
 *
 *   file I/O + exit   sys_open, sys_read, sys_close, sys_write, sys_exit,
 *                     sys_lseek. Building a scenario with -DNOLIBC_AON turns
 *                     those six static functions in nolibc/sys.h into extern
 *                     declarations, so every open()/read()/write()/close()/
 *                     lseek() -- and the exit() nolibc's startup runs when
 *                     main returns -- funnels into the wrappers here.
 *
 *   signals           sys_rt_sigaction, sys_setitimer, sys_rt_sigreturn (the
 *                     SA_RESTORER). Not part of nolibc's API: a program that
 *                     installs a handler declares them itself. A protected
 *                     program can only use signals through these wrappers,
 *                     since a `syscall` of rt_sigaction / setitimer /
 *                     rt_sigreturn outside the AoN region would be refused.
 *
 * ONE source file builds both PoC variants, selected by -DAON_DEFEND:
 *
 *   baseline (no -DAON_DEFEND)  each wrapper is a plain
 *                                  mov $nr,%eax ; syscall ; ret
 *                              with no ingress gate and no .note.aon region.
 *                              aon_mod sees no region and does not intervene:
 *                              the undefended control case.
 *
 *   defended (-DAON_DEFEND)     each wrapper becomes an AoN block with a
 *                              leading `ud2` ingress gate (0f 0b), and the
 *                              linked blocks form the AoN region
 *                              [__start_aon_text,__stop_aon_text), described
 *                              by a .note.aon descriptor aon_mod reads at exec.
 *                              aon_mod arms the thread at the ingress gate and
 *                              checks and disarms it at the egress gate; an
 *                              unarmed egress gate is refused, and so is any
 *                              `syscall` outside the AoN region.
 *
 * REQUIRED SYSTEM CALLS ONLY. Every wrapper lives in its own input section,
 * all with the SAME name `aon_text` (gas `unique,N`), so each can be included
 * individually. Linked with `--gc-sections -z start-stop-gc`, ld keeps only
 * the wrappers the program actually references (a program that never calls
 * write() gets no sys_write wrapper, so no `syscall` pinned to write at all;
 * a program that installs no signal handler gets none of the signal wrappers)
 * and gathers the survivors into ONE output section `aon_text`. `aon_text` is
 * a C identifier the default linker script does not mention, so ld places it
 * as an orphan next to .text, in the same R E segment, and defines
 * __start_aon_text / __stop_aon_text around it: the AoN region is contiguous
 * and holds nothing but the AoN blocks (each followed by its `ret`), by
 * construction. `-z start-stop-gc` is REQUIRED: without it the note's
 * __start_/__stop_ reference counts as a use of every `aon_text` section and
 * every wrapper is kept. Both builds use the same layout, so baseline and
 * defended keep identical placement.
 *
 * `execve` (nr 59) has NO wrapper here: it is not an intended system call of
 * the scenarios, so the only execve the process can invoke is through a REUSED
 * `syscall` (see cat.c, vectors A and B).
 *
 * Return contract (nolibc): the raw kernel value (>= 0, or -errno). The nolibc
 * functions in sys.h (read(), write(), ...) apply __sysret(), so errno
 * translation stays OUTSIDE the AoN blocks.
 *
 * Anatomy of the AoN block (defended), design property B3:
 *      ud2                 ingress gate (0f 0b): aon_mod arms the thread
 *      movl $nr, %eax      body: pins the system call number
 *      syscall             egress gate: the kernel entry of the protected
 *                          operation, the system call itself
 * followed by
 *      ret                 OUTSIDE the AoN block: the ordinary return to the
 *                          caller. It shares the `aon_text` section only
 *                          because it must follow the `syscall` in memory.
 * aon_mod identifies an egress gate by the address of the `syscall` itself, so
 * the `ret` plays no part in the check. The body contains no explicit control
 * transfer (static condition): no frame, no calls, no retry loop back onto the
 * `syscall`. The body pins the system call number only; arguments are not
 * validated (by design).
 *
 * With aon_mod loaded, a protected process may invoke a system call ONLY from
 * one of these egress gates, after passing its ingress gate: a `syscall`
 * anywhere else in the address space is refused (design property B1).
 *
 * tools/verify_aon.py discovers the ingress gates from the __aon_* symbols
 * (only the linked ones survive) and the bounds from __start_/__stop_aon_text;
 * it is run on the defended binary only.
 */

#ifdef AON_DEFEND
# define AON_GATE	ud2		/* ingress gate present in the defended build */
#else
# define AON_GATE			/* baseline: no ingress gate */
#endif

/* ======================================================================
 * AoN BLOCKS -- one `aon_text` input section each; the linked ones form the
 * AoN region [__start_aon_text, __stop_aon_text) in the defended build.
 *
 * Where the C arguments are already in the system call argument registers
 * (rdi, rsi, rdx), the public `sys_*` name is a second label on its block and
 * the caller's `call` lands directly on the ingress gate. Only
 * sys_rt_sigaction, whose 4th argument must move from rcx to r10, has a
 * marshaling stub, in its own ordinary .text section OUTSIDE the AoN region.
 * ====================================================================== */

/* ---------- int sys_open(const char *path, int flags, mode_t mode) ------
 * Invokes open (nr 2), not the openat(AT_FDCWD, ...) upstream nolibc prefers:
 * the wrapper is `sys_open`, so the system call is `open`. */
	.section	aon_text, "ax", @progbits, unique, 1
	.globl	__aon_open
	.type	__aon_open, @function
	.globl	sys_open
	.type	sys_open, @function
__aon_open:
sys_open:
	AON_GATE			/* INGRESS GATE (0f 0b) in defended build */
	movl	$2, %eax		/* body: system call nr = 2 (open)        */
	syscall				/* EGRESS GATE (open)                     */
	ret				/* outside the block: back to the caller  */
	.size	__aon_open, .-__aon_open
	.size	sys_open, .-sys_open

/* ---------- ssize_t sys_read(int fd, void *buf, size_t count) -----------
 * `sys_read_egress` marks the egress gate (the `syscall` instruction): that
 * is the vector-A target leaked to the attacker (cat.c). */
	.section	aon_text, "ax", @progbits, unique, 2
	.globl	__aon_read
	.type	__aon_read, @function
	.globl	sys_read
	.type	sys_read, @function
__aon_read:
sys_read:
	AON_GATE			/* INGRESS GATE (0f 0b) in defended build */
	movl	$0, %eax		/* body: system call nr = 0 (read)        */
	.globl	sys_read_egress
sys_read_egress:
	syscall				/* EGRESS GATE (read) == vector-A target  */
	ret				/* outside the block: back to the caller  */
	.size	__aon_read, .-__aon_read
	.size	sys_read, .-sys_read

/* ---------- int sys_close(int fd) --------------------------------------- */
	.section	aon_text, "ax", @progbits, unique, 3
	.globl	__aon_close
	.type	__aon_close, @function
	.globl	sys_close
	.type	sys_close, @function
__aon_close:
sys_close:
	AON_GATE			/* INGRESS GATE (0f 0b) in defended build */
	movl	$3, %eax		/* body: system call nr = 3 (close)       */
	syscall				/* EGRESS GATE (close)                    */
	ret				/* outside the block: back to the caller  */
	.size	__aon_close, .-__aon_close
	.size	sys_close, .-sys_close

/* ---------- ssize_t sys_write(int fd, const void *buf, size_t count) ---- */
	.section	aon_text, "ax", @progbits, unique, 4
	.globl	__aon_write
	.type	__aon_write, @function
	.globl	sys_write
	.type	sys_write, @function
__aon_write:
sys_write:
	AON_GATE			/* INGRESS GATE (0f 0b) in defended build */
	movl	$1, %eax		/* body: system call nr = 1 (write)       */
	syscall				/* EGRESS GATE (write)                    */
	ret				/* outside the block: back to the caller  */
	.size	__aon_write, .-__aon_write
	.size	sys_write, .-sys_write

/* ---------- void sys_exit(int status) [[noreturn]] ---------------------
 * exit takes the status in rdi, where C already put it. The system call
 * terminates the thread (user-visible, the thread does not continue), so the
 * trailing `ret` is unreachable; it is kept so that, as for every other
 * wrapper, nothing can fall through from this block into the next one in
 * `aon_text`. The kernel keeps only the low 8 bits of the status, so the mask
 * nolibc applied is dropped: the defended cat exits with the same status as
 * the baseline. */
	.section	aon_text, "ax", @progbits, unique, 5
	.globl	__aon_exit
	.type	__aon_exit, @function
	.globl	sys_exit
	.type	sys_exit, @function
__aon_exit:
sys_exit:
	AON_GATE			/* INGRESS GATE (0f 0b) in defended build */
	movl	$60, %eax		/* body: system call nr = 60 (exit)       */
	syscall				/* EGRESS GATE (exit): does not return    */
	ret				/* outside the block; unreachable         */
	.size	__aon_exit, .-__aon_exit
	.size	sys_exit, .-sys_exit

/* ---------- off_t sys_lseek(int fd, off_t offset, int whence) -----------
 * Not a cat intended system call: the cost benchmark rewinds its sink file
 * with it (evaluation/bench), so only the bench links it. */
	.section	aon_text, "ax", @progbits, unique, 9
	.globl	__aon_lseek
	.type	__aon_lseek, @function
	.globl	sys_lseek
	.type	sys_lseek, @function
__aon_lseek:
sys_lseek:
	AON_GATE			/* INGRESS GATE (0f 0b) in defended build */
	movl	$8, %eax		/* body: system call nr = 8 (lseek)       */
	syscall				/* EGRESS GATE (lseek)                    */
	ret				/* outside the block: back to the caller  */
	.size	__aon_lseek, .-__aon_lseek
	.size	sys_lseek, .-sys_lseek

/* ======================================================================
 * SIGNALS -- what a protected program needs to install and return from a
 * handler. Same AoN region as the blocks above.
 * ====================================================================== */

/* ---------- long sys_rt_sigaction(int sig, const void *act, void *oact,
 *                                  size_t sigsetsize) ----------------------
 * Fourth argument: C passes it in rcx, the kernel wants it in r10. The
 * marshaling stub lives OUTSIDE the AoN region and tail-jumps to the ingress
 * gate: the `ret` after the block returns straight to sys_rt_sigaction's
 * caller. */
	.section	.text.sys_rt_sigaction, "ax", @progbits
	.globl	sys_rt_sigaction
	.type	sys_rt_sigaction, @function
sys_rt_sigaction:
	movq	%rcx, %r10		/* MARSHALING: sigsetsize -> r10 (4th arg) */
	jmp	__aon_rt_sigaction
	.size	sys_rt_sigaction, .-sys_rt_sigaction

	.section	aon_text, "ax", @progbits, unique, 6
	.globl	__aon_rt_sigaction
	.type	__aon_rt_sigaction, @function
__aon_rt_sigaction:
	AON_GATE			/* INGRESS GATE (0f 0b) in defended build */
	movl	$13, %eax		/* body: system call nr = 13 (rt_sigaction) */
	syscall				/* EGRESS GATE (rt_sigaction)             */
	ret				/* outside the block: back to the caller  */
	.size	__aon_rt_sigaction, .-__aon_rt_sigaction

/* ---------- long sys_setitimer(int which, const void *new, void *old) ---- */
	.section	aon_text, "ax", @progbits, unique, 7
	.globl	__aon_setitimer
	.type	__aon_setitimer, @function
	.globl	sys_setitimer
	.type	sys_setitimer, @function
__aon_setitimer:
sys_setitimer:
	AON_GATE			/* INGRESS GATE (0f 0b) in defended build */
	movl	$38, %eax		/* body: system call nr = 38 (setitimer)  */
	syscall				/* EGRESS GATE (setitimer)                */
	ret				/* outside the block: back to the caller  */
	.size	__aon_setitimer, .-__aon_setitimer
	.size	sys_setitimer, .-sys_setitimer

/* ---------- sys_rt_sigreturn: the SA_RESTORER, never returns on success ---
 * Installed as the SA_RESTORER, never called from C: the handler's `ret`
 * lands on it through frame->pretcode. On success rt_sigreturn restores the
 * interrupted context (user-visible, the thread continues elsewhere) and never
 * comes back, so the code after the `syscall` is unreachable then.
 *
 * But if a signal handler is run while THIS block is armed (between its
 * ingress and egress gates), aon_mod disarms the thread and the rt_sigreturn
 * is refused (-ENOSYS, every other register intact, rsp still frame+8). A
 * plain `ret` after it would crash; instead the block is executed again
 * through its ingress gate by the `jmp` that follows it (outside the block,
 * like the `ret` of the other wrappers). */
	.section	aon_text, "ax", @progbits, unique, 8
	.globl	__aon_rt_sigreturn
	.type	__aon_rt_sigreturn, @function
	.globl	sys_rt_sigreturn
	.type	sys_rt_sigreturn, @function
__aon_rt_sigreturn:
sys_rt_sigreturn:
	AON_GATE			/* INGRESS GATE (0f 0b) in defended build */
	movl	$15, %eax		/* body: system call nr = 15 (rt_sigreturn) */
	syscall				/* EGRESS GATE: only returns if refused   */
	jmp	__aon_rt_sigreturn	/* outside the block: retry via the gate  */
	.size	__aon_rt_sigreturn, .-__aon_rt_sigreturn
	.size	sys_rt_sigreturn, .-sys_rt_sigreturn

#ifdef AON_DEFEND
/* AoN region descriptor aon_mod reads at exec: owner "AoN",
 * type NT_AON_REGION (kernel/aon.h), bounds as 32-bit offsets from the
 * descriptor. The bounds are the linker-generated __start_/__stop_aon_text, so
 * they bracket exactly the AoN blocks that survived --gc-sections. The section
 * is allocated ("a"), so it lands in a PT_NOTE segment; the Makefile checks it
 * survives --gc-sections. */
	.section	.note.aon, "a", @note
	.balign	4
	.long	4			/* n_namesz: "AoN\0"          */
	.long	8			/* n_descsz: two .long below  */
	.long	1			/* n_type:   NT_AON_REGION    */
	.asciz	"AoN"
1:	.long	__start_aon_text - 1b	/* region start, from here    */
	.long	__stop_aon_text - 1b	/* region end, from here      */
#endif /* AON_DEFEND */

	.section	.note.GNU-stack,"",@progbits
