/*
 * gadget.S - an ordinary routine hiding a MISALIGNED site (x86_64, AT&T).
 *
 * benign_compute's immediate operand holds the bytes 0f 05 c3 (`syscall ;
 * ret`). Entered two bytes in -- off the intended instruction boundary -- the
 * CPU decodes a real `syscall` the programmer never wrote. No hardening here,
 * so it runs (vector B).
 */

	.text

	.globl	benign_compute
	.type	benign_compute, @function
benign_compute:
	movabs $0x9090909090C3050F, %rax	/* +2 = 0f 05 c3 = syscall; ret   */
	ret
	.size	benign_compute, .-benign_compute

	.section	.note.GNU-stack,"",@progbits
