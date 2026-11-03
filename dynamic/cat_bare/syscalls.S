/*
 * syscalls.S - direct system call wrappers (x86_64, AT&T syntax).
 *
 * In the sibling `cat` scenario the victim reaches the kernel through glibc's
 * read()/write()/open()/close() wrappers, so every file-I/O `syscall` lives
 * inside libc.so.6. Here the program issues those system calls *itself*: each
 * wrapper pins its system call number and runs the `syscall` instruction in the
 * program's own .text. The program is still an ordinary dynamically linked
 * glibc executable (printf/strcmp/... still resolve to libc.so.6) -- only the
 * four file-I/O system calls move out of libc into these bare wrappers.
 *
 * These are *not* hardened named wrappers: there is no ingress gate, no AoN
 * block, no defense -- this is still the attacker-wins baseline. The point of
 * the scenario is only to relocate the aligned `syscall` of vector A out of
 * libc and into the program binary, so the reuse target is the program's own
 * (unhardened) read wrapper rather than glibc's.
 *
 * The System V C calling convention and the Linux system call convention agree
 * on the first three argument registers (%rdi, %rsi, %rdx) and differ only on
 * the fourth (%rcx vs %r10); open/read/write/close take at most three
 * arguments, so each wrapper just pins %eax and executes `syscall`. The system
 * call's return value is left in %rax, which is also the C return register, so
 * a negative return propagates to the caller as a negative long (raw kernel
 * errno, not set through glibc's errno).
 */

	.text

	.globl	raw_open
	.type	raw_open, @function
raw_open:				/* long raw_open(const char *, int, int) */
	movl	$2, %eax		/* system call nr 2 = open              */
	syscall
	ret
	.size	raw_open, .-raw_open

	.globl	raw_read
	.type	raw_read, @function
raw_read:				/* long raw_read(int, void *, unsigned long) */
	movl	$0, %eax		/* system call nr 0 = read              */
	syscall
	ret
	.size	raw_read, .-raw_read

	.globl	raw_write
	.type	raw_write, @function
raw_write:				/* long raw_write(int, const void *, unsigned long) */
	movl	$1, %eax		/* system call nr 1 = write             */
	syscall
	ret
	.size	raw_write, .-raw_write

	.globl	raw_close
	.type	raw_close, @function
raw_close:				/* long raw_close(int)                   */
	movl	$3, %eax		/* system call nr 3 = close             */
	syscall
	ret
	.size	raw_close, .-raw_close

	.section	.note.GNU-stack,"",@progbits
