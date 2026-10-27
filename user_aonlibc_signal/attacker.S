/*
 * attacker.S - Simulated attacker primitive (x86_64, AT&T syntax).
 *
 * The PoC page allows the attacker's capabilities to be *simulated* with
 * purposely placed asm blocks instead of a real memory corruption exploit.
 * `hijack` models exactly two capabilities of the threat model:
 *
 *   1. Set an arbitrary register state: load chosen values into the system
 *      call registers (%rax = nr, %rdi/%rsi/%rdx = arguments).
 *   2. Redirect control flow to an arbitrary address: transfer execution to
 *      a chosen `syscall` instruction, as an overwritten return address / ROP
 *      pivot would.
 *
 * void hijack(void *gadget, long nr, long a1, long a2, long a3)
 *              rdi           rsi      rdx     rcx     r8
 *
 * `hijack` sets up the registers, then `jmp`s onto the chosen `syscall`. The
 * `ret` that follows it pops the return address `call hijack` pushed -- so
 * control returns cleanly to the caller and the program keeps running as if
 * nothing happened (a stealthy, side-effect-only reuse).
 */

	.text
	.globl	hijack
	.type	hijack, @function
hijack:
	movq	%rdi, %r11		/* r11 = target `syscall` instruction    */
	movq	%rsi, %rax		/* rax = system call nr                  */
	movq	%rdx, %rdi		/* arg1 (e.g. path)                      */
	movq	%rcx, %rsi		/* arg2 (e.g. argv)                      */
	movq	%r8,  %rdx		/* arg3 (e.g. envp)                      */
	jmp	*%r11			/* control-flow hijack onto the gadget;  */
					/* the `ret` after it returns to our caller */
	.size	hijack, .-hijack

	.section	.note.GNU-stack,"",@progbits
