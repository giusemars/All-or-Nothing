/*
 * syscall_latency.c - reference costs on the test machine (evaluation row P0).
 *
 * Pulled back from 9th_run (report/experiments/syscall_latency.c). glibc, no
 * aonlibc: it is never protected, and it measures what every protected call
 * is built from.
 *
 *   syscall_latency <op>
 *
 *   timer    one serialized TSC read pair with nothing between (the
 *            measurement overhead, same instruction sequence as bench)
 *   null     getpid (nr 39) issued with a raw `syscall`
 *   badfd    write(-1, buf, 0) with a raw `syscall`: what bench loops on
 *   enosys   invalid system call nr (-1): the entry/exit path alone; also
 *            what a call refused by aon_mod (default mode) costs
 *   ud2      `ud2` -> #UD -> SIGILL handler -> rt_sigreturn: a trap-based
 *            gate handled in user space. NOT the AoN ingress gate (aon_mod
 *            handles the #UD in the kernel, no signal is delivered); a
 *            loose upper bound only.
 *   int3     `int3` -> #BP -> SIGTRAP handler -> rt_sigreturn: the same path
 *            through another exception vector; ud2 - int3 isolates what is
 *            specific to #UD on this machine (e.g. a hypervisor intercept)
 *
 * Every operation is timed on its own with the TSC (as bench stream), so each
 * sample includes the timer; the samples go to stdout as raw uint32 ticks,
 * CHUNK at a time, until the reader closes the pipe. This is the model of
 * batch_means.py, which decides the length of the run. The TSC calibration
 * is tsc_calib.c.
 *
 * Exit status: 0 once stdout is closed, 1 on a usage error.
 *
 * Build & run:  gcc -O2 -o syscall_latency syscall_latency.c
 *               batch_means.py -- taskset -c 2 ./syscall_latency <op>
 */
#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <ucontext.h>
#include <unistd.h>

#define CHUNK 4096 /* samples per write (16 KiB) */

static unsigned int ticks[CHUNK];

static inline unsigned long tsc_begin(void)
{
	unsigned int lo, hi;

	__asm__ volatile("lfence; rdtsc; lfence" : "=a"(lo), "=d"(hi) :: "memory");
	return ((unsigned long)hi << 32) | lo;
}

static inline unsigned long tsc_end(void)
{
	unsigned int lo, hi, aux;

	__asm__ volatile("rdtscp; lfence" : "=a"(lo), "=d"(hi), "=c"(aux) :: "memory");
	return ((unsigned long)hi << 32) | lo;
}

static void on_ill(int s, siginfo_t *i, void *c)
{
	(void)s;
	(void)i;
	((ucontext_t *)c)->uc_mcontext.gregs[REG_RIP] += 2;
}

static void on_trap(int s)
{
	(void)s;
}

/* Write len bytes to stdout; -1 once stdout is gone. */
static int dump(const void *p, size_t len)
{
	const char *c = p;

	while (len) {
		ssize_t n = write(1, c, len);
		if (n <= 0)
			return -1;
		c += n;
		len -= n;
	}
	return 0;
}

/* Time body once per sample, CHUNK samples per write, until stdout closes. */
#define STREAM(body)                                                         \
	do {                                                                 \
		for (;;) {                                                   \
			for (int i_ = 0; i_ < CHUNK; i_++) {                  \
				unsigned long t0_ = tsc_begin();             \
				body;                                        \
				ticks[i_] = tsc_end() - t0_;                 \
			}                                                    \
			if (dump(ticks, sizeof(ticks)))                      \
				return 0;                                    \
		}                                                            \
	} while (0)

int main(int argc, char **argv)
{
	char c;
	long r;
	struct sigaction sa = {0};
	const char *op = argc == 2 ? argv[1] : "";

	if (!strcmp(op, "timer"))
		STREAM((void)0);
	if (!strcmp(op, "null"))
		STREAM(__asm__ volatile("syscall" : "=a"(r) : "a"(39L)
					: "rcx", "r11", "memory"));
	if (!strcmp(op, "badfd"))
		STREAM(__asm__ volatile("syscall" : "=a"(r)
					: "a"(1L), "D"(-1L), "S"(&c), "d"(0L)
					: "rcx", "r11", "memory"));
	if (!strcmp(op, "enosys"))
		STREAM(__asm__ volatile("syscall" : "=a"(r) : "a"(-1L)
					: "rcx", "r11", "memory"));
	if (!strcmp(op, "ud2")) {
		sa.sa_sigaction = on_ill;
		sa.sa_flags = SA_SIGINFO;
		sigaction(SIGILL, &sa, 0);
		STREAM(__asm__ volatile("ud2" ::: "memory"));
	}
	if (!strcmp(op, "int3")) {
		sa.sa_handler = on_trap;
		sigaction(SIGTRAP, &sa, 0);
		STREAM(__asm__ volatile("int3" ::: "memory"));
	}
	fprintf(stderr, "usage: syscall_latency <timer|null|badfd|enosys|ud2|int3>\n");
	return 1;
}
