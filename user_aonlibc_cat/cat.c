/*
 * cat.c - aonlibc `cat` victim + attack driver for the All-or-Nothing Code
 *         Blocks proof of concept.
 *
 * ACADEMIC BASELINE (undefended control case) and the basis for further
 * scenarios. It has two parts:
 *
 *   - the victim is linked -nostdlib -static against the hardened syscall
 *     library in ../aonlibc (vendored nolibc + aon_syscalls.S) and invokes
 *     every system call through its hardened named wrappers: open / read /
 *     write / close / exit. Those are its INTENDED system calls.
 *   - it is invoked like `cat <filename>`: it opens that file, reads it in a
 *     loop, writes each chunk to stdout, and closes it. Two reserved operands
 *     instead select the attack methodology:
 *       <filename>  run the real behavior on that file, touch nothing extra;
 *       aligned     jump onto the egress gate (the `syscall`) of the read
 *                   wrapper, past its ingress gate and body: an aligned
 *                   gadget, i.e. an unintended execution of the AoN block
 *                   -> vector A (detected: unarmed egress gate);
 *       misaligned  jump onto the misaligned site hidden in benign_compute
 *                   (gadget.S) -> vector B (detected: outside the AoN
 *                   region).
 *
 * The attacker's goal is an `execve` (system call nr 59) -- not an intended
 * system call: the victim never invokes it itself. A successful attack
 * replaces the process image with an attacker-chosen program (/bin/echo here,
 * so the win is visible and harmless); a blocked attack (defended build +
 * aon_mod loaded) never runs the execve -- aon_mod refuses the system call (by
 * default it rewrites the number so the dispatch returns -ENOSYS), control
 * falls back to the caller, and the process image is left intact. In the
 * defended build BOTH vectors are blocked: vector A because the thread never
 * passed the ingress gate, vector B because the `syscall` is not in the AoN
 * region at all.
 *
 * Build & run: see Makefile.  Usage: ./cat <filename|aligned|misaligned>
 */
#include "nolibc.h"
#include "cat.h"

/* execve payload. Harmless and observable: on a successful hijack the process
 * image is replaced by `/bin/echo`, which prints this line and exits. No
 * network, no privileged action -- it only demonstrates that control reached
 * an execve the victim never intended to invoke. */
static char *const EVIL_ARGV[] = {
	"/bin/echo",
	"[attacker] execve() hijack succeeded -- process image replaced",
	0,
};
static char *const EVIL_ENVP[] = { 0 };

/* Tiny string compare for argv parsing, with no system call (keeps the
 * victim's system calls to exactly the intended ones). */
static int streq(const char *a, const char *b)
{
	while (*a && *a == *b) {
		a++;
		b++;
	}
	return *a == *b;
}

/* The genuine cat behavior: stream `path` to stdout through the open / read /
 * write / close wrappers. Returns 0 on success. */
static int do_cat(const char *path)
{
	char buf[256];

	int fd = open(path, O_RDONLY);
	if (fd < 0) {
		write(2, "cat: open failed\n", 17);
		return 1;
	}

	for (;;) {
		long n = read(fd, buf, sizeof(buf));
		if (n < 0) {
			write(2, "cat: read failed\n", 17);
			close(fd);
			return 2;
		}
		if (n == 0)
			break;			/* EOF */
		write(1, buf, (size_t)n);
	}

	close(fd);
	return 0;
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		write(2, "usage: cat <filename|aligned|misaligned>\n", 41);
		return 1;
	}

	const char *arg = argv[1];

	if (streq(arg, "aligned")) {
		/* Vector A: jump straight onto the egress gate of the read
		 * wrapper (past its `ud2` ingress gate and its `mov` body) with
		 * %rax = 59 (execve), %rdi/%rsi/%rdx = path/argv/envp.
		 *
		 *   baseline  -> the system call runs: execve replaces the process.
		 *   defended  -> the thread was never armed at the ingress gate,
		 *                so aon_mod refuses this system call (nr ->
		 *                -ENOSYS) and it is NOT an execve; control returns
		 *                here instead. THIS is what the thesis hardens. */
		hijack((void *)sys_read_egress, 59,
		       (long)EVIL_ARGV[0], (long)EVIL_ARGV, (long)EVIL_ENVP);
		/* Reached only when the execve did NOT happen: on the defended build
		 * because aon_mod blocked it (the expected "attack blocked"
		 * outcome), or on the baseline only if execve itself failed. */
		write(2, "cat: aligned hijack blocked (no execve)\n", 40);
		return 3;
	}

	if (streq(arg, "misaligned")) {
		/* Vector B: jump onto the misaligned `syscall` two bytes into
		 * benign_compute's immediate operand -- a misaligned site OUTSIDE
		 * the AoN region.
		 *
		 *   baseline  -> the system call runs: execve replaces the process.
		 *   defended  -> aon_mod refuses every `syscall` of a protected
		 *                process outside the AoN region, so this one is
		 *                refused too and control returns here. */
		hijack((void *)((char *)benign_compute + 2), 59,
		       (long)EVIL_ARGV[0], (long)EVIL_ARGV, (long)EVIL_ENVP);
		/* Reached only when the execve did NOT happen: on the defended build
		 * because aon_mod blocked it, or on the baseline only if execve
		 * itself failed. */
		write(2, "cat: misaligned hijack blocked (no execve)\n", 43);
		return 3;
	}

	/* Not a reserved attack operand: run the genuine cat on it. */
	return do_cat(arg);
}
