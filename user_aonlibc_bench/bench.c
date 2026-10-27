/*
 * bench.c - aonlibc cost benchmark for the All-or-Nothing Code Blocks PoC
 *           (evaluation rows P1, P2, P3; see evaluation/cost/).
 *
 * A loop of protected calls: every iteration invokes the hardened named
 * wrapper of `write`. By default with fd -1 and count 0, so the kernel does as
 * little as a real system call can (fd lookup, -EBADF). The fixed cost of the
 * AoN enforcement is then the largest possible fraction of the call: the
 * figure is the worst case of the relative overhead.
 *
 * With a SIZE > 0 the writes are real: SIZE bytes each to the file SINK
 * (opened, created and truncated before any measurement). The file never
 * grows past MAX bytes: once the next write would cross MAX, the hardened
 * named wrapper of `lseek` rewinds it to offset 0, outside the timed window,
 * so every timed call is a `write` of SIZE bytes into pages already in the
 * page cache. The fixed AoN cost against a cost growing with SIZE.
 *
 * The same source builds four binaries (Makefile):
 *
 *   bench             baseline: plain wrappers, no AoN region, not policed
 *   bench_defended    AoN blocks + .note.aon: every call passes the `ud2`
 *                     ingress gate (#UD, arm) and the `syscall` egress gate
 *                     (check, disarm) of aon_mod
 *   bench_seccomp     baseline wrappers + a seccomp filter on the system call
 *                     number (allow only the required system calls)
 *   bench_seccomp_ip  as bench_seccomp, and the filter also pins each allowed
 *                     number to the instruction pointer after the `syscall`
 *                     of its own wrapper (the seccomp analogue of B1)
 *
 * The filter is installed before any measurement, so only its per-call cost
 * is measured, not its installation.
 *
 * Operands (the binary only ever uses its required system calls, so the
 * defended build is never refused):
 *
 *   loop <N> [SIZE SINK MAX]
 *              N calls, nothing else: timed from outside (perf stat), the
 *              slope over several N is the cost per call
 *   lat <N> [SIZE SINK MAX]
 *              N calls, each timed with the TSC (rdtscp ... lfence; rdtsc is
 *              not a system call, so the defended build can use it); the N
 *              32-bit tick deltas are written raw to stdout
 *   nop <N>    as lat with no call between the two reads of the TSC: the
 *              cost of the timing itself
 *   stream [SIZE SINK MAX]
 *   stream-nop as lat / nop, without end: the samples go to stdout in chunks
 *              of STREAM_CHUNK until the reader closes the pipe. This is the
 *              model of evaluation/cost/batch_means.py, which decides the
 *              length of the run
 *   block      read(0, ...) once: keeps a process alive (with an AoN region
 *              in the defended build) for as long as stdin stays open
 *
 * SIZE 0 is the default write(-1, buf, 0) (SINK and MAX are ignored); SIZE is
 * at most MAX_SIZE.
 *
 * Exit status: 0, 1 on a usage error, 2 if the sink cannot be used (open
 * failed, short write) or the seccomp filter is not installed.
 */
#include "nolibc.h"

#ifdef BENCH_SECCOMP
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#endif

/* The wrappers (aonlibc/aon_syscalls.S) are called directly, so the loop
 * measures the wrapper and nothing of nolibc's errno handling. */
extern long sys_write(int fd, const void *buf, unsigned long count);
extern long sys_read(int fd, void *buf, unsigned long count);
extern int sys_open(const char *path, int flags, mode_t mode);
extern off_t sys_lseek(int fd, off_t offset, int whence);

#define MAX_LAT (1UL << 22) /* lat/nop: at most 4 Mi samples (16 MiB bss) */
static unsigned int ticks[MAX_LAT];

#define STREAM_CHUNK 4096 /* stream: samples per write (16 KiB) */

#define MAX_SIZE (1UL << 20) /* largest SIZE of a real write (1 MiB) */
static char buf[MAX_SIZE];

/* The write every call makes: write(-1, buf, 0) until sink_open() points it at
 * a file. sink_off is the file offset, rewound before it would cross
 * sink_max. */
static int sink_fd = -1;
static unsigned long sink_size, sink_max, sink_off;

static int streq(const char *a, const char *b)
{
	while (*a && *a == *b) {
		a++;
		b++;
	}
	return *a == *b;
}

/* Serialized TSC reads: rdtscp waits for the earlier instructions, the
 * lfence keeps the later ones from starting before the read. */
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

static void die(const char *msg)
{
	sys_write(2, msg, strlen(msg));
	exit(2);
}

/* Real writes of size bytes to the file path, kept within max bytes. Before
 * the seccomp filter, so `open` need not be allowed. */
static void sink_open(unsigned long size, const char *path, unsigned long max)
{
	if (!size)
		return;
	sink_fd = sys_open(path, O_RDWR | O_CREAT | O_TRUNC, 0600);
	if (sink_fd < 0)
		die("bench: cannot open the sink\n");
	memset(buf, 'a', size); /* real pages, not the shared zero page */
	sink_size = size;
	sink_max = max;
}

/* After each call, outside the timed window: account for a real write and
 * rewind the file before the next one would grow it past sink_max. */
static inline void sink_advance(long n)
{
	if (sink_fd < 0)
		return;
	if (n != (long)sink_size)
		die("bench: short write to the sink\n");
	sink_off += n;
	if (sink_off + sink_size > sink_max) {
		sys_lseek(sink_fd, 0, SEEK_SET);
		sink_off = 0;
	}
}

/* Write len bytes to stdout; -1 once stdout is gone. */
static int dump(const void *p, unsigned long len)
{
	const char *c = p;

	while (len) {
		long n = sys_write(1, c, len);
		if (n <= 0)
			return -1;
		c += n;
		len -= n;
	}
	return 0;
}

#ifdef BENCH_SECCOMP
/* Raw system calls, outside aonlibc: this build is a baseline (no AoN
 * region), so aon_mod never polices it. */
#define NR_prctl   157
#define NR_seccomp 317

/* Offsets in struct seccomp_data. */
#define SD_NR   0
#define SD_ARCH 4
#define SD_IP_L 8
#define SD_IP_H 12

/* Allow the system call nr @nr, and with @ip != 0 only if the instruction
 * pointer (the address after the `syscall`) is @ip. 4 instructions. */
#define ALLOW_NR_AT(nr, ip)                                                  \
	BPF_STMT(BPF_LD | BPF_W | BPF_ABS, SD_NR),                           \
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (nr), 0, 3),                     \
	BPF_STMT(BPF_LD | BPF_W | BPF_ABS, SD_IP_L),                         \
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (ip), 0, 1),                     \
	BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)

#define ALLOW_NR(nr)                                                         \
	BPF_STMT(BPF_LD | BPF_W | BPF_ABS, SD_NR),                           \
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (nr), 0, 1),                     \
	BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)

#ifdef BENCH_SECCOMP_IP
/* Address after the `syscall` of a baseline wrapper: `mov $nr,%eax` (5 bytes)
 * then `syscall` (2 bytes). Checked against the bytes, so a change of the
 * wrapper layout fails loudly instead of measuring a filter that kills. */
static unsigned int egress_ip(const void *wrapper)
{
	const unsigned char *b = wrapper;

	if (b[0] != 0xb8 || b[5] != 0x0f || b[6] != 0x05) {
		sys_write(2, "bench: unexpected wrapper layout\n", 33);
		exit(2);
	}
	return (unsigned int)(unsigned long)(b + 7);
}
#endif

static void install_filter(void)
{
	/* Refused system calls get -ENOSYS, like aon_mod's default. */
#ifdef BENCH_SECCOMP_IP
	unsigned int w = egress_ip(sys_write), r = egress_ip(sys_read);
	extern void sys_exit(int);
	unsigned int e = egress_ip(sys_exit), l = egress_ip(sys_lseek);
	struct sock_filter f[] = {
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, SD_ARCH),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
		/* non-PIE static binary: every wrapper is below 4 GiB */
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, SD_IP_H),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 0),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ENOSYS),
		ALLOW_NR_AT(1, w),
		ALLOW_NR_AT(0, r),
		ALLOW_NR_AT(60, e),
		ALLOW_NR_AT(8, l),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ENOSYS),
	};
#else
	struct sock_filter f[] = {
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, SD_ARCH),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
		ALLOW_NR(1),  /* write */
		ALLOW_NR(0),  /* read  */
		ALLOW_NR(60), /* exit  */
		ALLOW_NR(8),  /* lseek */
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ENOSYS),
	};
#endif
	struct sock_fprog prog = {
		.len = sizeof(f) / sizeof(f[0]),
		.filter = f,
	};

	if (my_syscall5(NR_prctl, PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) ||
	    my_syscall3(NR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog)) {
		sys_write(2, "bench: seccomp filter not installed\n", 36);
		exit(2);
	}
}
#endif /* BENCH_SECCOMP */

/* n timed calls into ticks[0..n). */
static void measure(unsigned long n, int nop)
{
	unsigned long i, t0;
	long w;

	if (nop) {
		for (i = 0; i < n; i++) {
			t0 = tsc_begin();
			ticks[i] = tsc_end() - t0;
		}
	} else {
		for (i = 0; i < n; i++) {
			t0 = tsc_begin();
			w = sys_write(sink_fd, buf, sink_size);
			ticks[i] = tsc_end() - t0;
			sink_advance(w);
		}
	}
}

/* Timed calls until stdout is closed (the reader decides the length). */
static void stream(int nop)
{
	do
		measure(STREAM_CHUNK, nop);
	while (!dump(ticks, STREAM_CHUNK * sizeof(ticks[0])));
}

static int usage(void)
{
	static const char msg[] =
		"usage: bench <loop|lat> <N> [SIZE SINK MAX] | bench nop <N>\n"
		"       bench stream [SIZE SINK MAX] | bench <stream-nop|block>\n";

	sys_write(2, msg, sizeof(msg) - 1);
	return 1;
}

/* The optional SIZE SINK MAX operands at argv[0..2]; nargs is 0 or 3. */
static int sink_args(int nargs, char **argv)
{
	unsigned long size;

	if (nargs == 0)
		return 0;
	if (nargs != 3)
		return -1;
	size = atol(argv[0]);
	if (size > MAX_SIZE)
		return -1;
	sink_open(size, argv[1], atol(argv[2]));
	return 0;
}

int main(int argc, char **argv)
{
	char c;
	unsigned long n = 0, i;
	int nop;

	if (argc == 2 && streq(argv[1], "block")) {
#ifdef BENCH_SECCOMP
		install_filter();
#endif
		sys_read(0, &c, 1);
		return 0;
	}
	if (argc < 2)
		return usage();
	if (streq(argv[1], "stream") || streq(argv[1], "stream-nop")) {
		nop = argv[1][6] == '-';
		if (nop ? argc != 2 : sink_args(argc - 2, argv + 2))
			return usage();
	} else {
		if (argc < 3)
			return usage();
		n = atol(argv[2]);
		nop = streq(argv[1], "nop");
		if (!nop && !streq(argv[1], "loop") && !streq(argv[1], "lat"))
			return usage();
		if (nop ? argc != 3 : sink_args(argc - 3, argv + 3))
			return usage();
	}
#ifdef BENCH_SECCOMP
	install_filter();
#endif
	if (streq(argv[1], "stream") || streq(argv[1], "stream-nop")) {
		stream(nop);
		return 0;
	}
	if (streq(argv[1], "loop")) {
		for (i = 0; i < n; i++)
			sink_advance(sys_write(sink_fd, buf, sink_size));
		return 0;
	}
	if (n > MAX_LAT)
		return usage();
	measure(n, nop);
	dump(ticks, n * sizeof(ticks[0]));
	return 0;
}
