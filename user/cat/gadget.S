/*
 * gadget.S - An ordinary victim routine that hides a MISALIGNED site
 * (x86_64, AT&T syntax).
 *
 * benign_compute's immediate operand contains the bytes 0f 05 c3 (`syscall ;
 * ret`). Entered two bytes in -- not at an intended instruction boundary --
 * the CPU decodes them as a real `syscall`: a misaligned gadget. It is
 * application code, not part of the hardened syscall library (../../aonlibc), so
 * it lies outside the AoN region in the defended build too.
 */

	.text

/* ------------------------------------------------------------------------
 * This is a MISALIGNED site: a `syscall` the programmer never wrote, present
 * only as a byte-level accident. It is not an AoN block, so no ingress gate
 * guards it. In the defended build it is blocked anyway: aon_mod refuses
 * every `syscall` of a protected process outside the AoN region (design
 * property B1). In the baseline it works.
 * ------------------------------------------------------------------------ */
	.globl	benign_compute
	.type	benign_compute, @function
benign_compute:
	movabs $0x9090909090C3050F, %rax
	ret				/* natural return of benign_compute      */
	.size	benign_compute, .-benign_compute

	.section	.note.GNU-stack,"",@progbits
