/*
 * tsc_calib.c - TSC calibration of the test machine (evaluation row P0).
 *
 * Prints the TSC frequency in ticks per ns, measured against CLOCK_MONOTONIC:
 * the median of REPS windows of 100 ms. analyze_cost.py converts every tick
 * count of the run (user_aonlibc_bench/bench and syscall_latency, which time
 * with the TSC: the defended bench cannot call clock_gettime, it would be
 * refused) to ns with it.
 *
 * Build & run:  gcc -O2 -o tsc_calib tsc_calib.c
 *               taskset -c 2 ./tsc_calib
 */
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define REPS 11

static double now(void)
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);
	return t.tv_sec * 1e9 + t.tv_nsec;
}

static unsigned long tsc(void)
{
	unsigned int lo, hi;

	__asm__ volatile("lfence; rdtsc; lfence" : "=a"(lo), "=d"(hi) :: "memory");
	return ((unsigned long)hi << 32) | lo;
}

static int cmp(const void *a, const void *b)
{
	double x = *(const double *)a, y = *(const double *)b;

	return (x > y) - (x < y);
}

int main(void)
{
	double v[REPS];

	for (int k = 0; k < REPS; k++) {
		double t0 = now();
		unsigned long c0 = tsc();

		while (now() - t0 < 1e8) /* 100 ms each */
			;
		v[k] = (tsc() - c0) / (now() - t0);
	}
	qsort(v, REPS, sizeof(*v), cmp);
	printf("%.6f\n", v[REPS / 2]);
	return 0;
}
