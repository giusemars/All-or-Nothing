# aonlibc cost benchmark for "All-or-Nothing Code Blocks" (evaluation rows
# P1-P3, driven by ../cost/run_cost.sh).
#
# bench.c is a loop of calls to the hardened named wrapper of `write` (see
# bench.c). Same layout and flags as ../../user/cat: -nostdlib -static
# against ../../aonlibc, --gc-sections -z start-stop-gc so only the wrappers of
# the required system calls (open, read, write, lseek, exit) are linked. Four
# binaries:
#
#   bench             baseline: plain wrappers, no AoN region
#   bench_defended    AoN blocks + .note.aon (needs aon_mod loaded), checked
#                     by verify_aon.py and readelf like cat_defended
#   bench_seccomp     baseline wrappers + seccomp filter on the system call nr
#   bench_seccomp_ip  as bench_seccomp, nr also pinned to its wrapper's
#                     `syscall` by the instruction pointer
#
# -O2, unlike the scenarios (-O0): the loop around the wrapper is part of
# every measurement, so keep it short. The wrappers are assembly either way.
#
#   make             build all four
#   make clean

CC      := gcc
AONLIBC := ../../aonlibc
NOLIBC  := $(AONLIBC)/nolibc
VERAON  := ../../tools/verify_aon.py

CFLAGS  := -O2 -g -Wall -Wextra -fno-pie -fcf-protection=none \
           -ffunction-sections -fdata-sections -I$(NOLIBC) -DNOLIBC_AON
ASFLAGS := -g
LDFLAGS := -nostdlib -static -no-pie -Wl,--gc-sections -Wl,-z,start-stop-gc

.PHONY: all clean
all: bench bench_defended bench_seccomp bench_seccomp_ip

# ---- Baseline -----------------------------------------------------------
bench: bench.o aon_syscalls.o
	$(CC) $(LDFLAGS) -o $@ $^

bench.o: bench.c
	$(CC) $(CFLAGS) -c $< -o $@

aon_syscalls.o: $(AONLIBC)/aon_syscalls.S
	$(CC) $(ASFLAGS) -c $< -o $@

# ---- Defended -----------------------------------------------------------
bench_defended: bench.o aon_syscalls.aon.o
	$(CC) $(LDFLAGS) -o $@ bench.o aon_syscalls.aon.o
	$(VERAON) $@
	@readelf -n $@ | grep -q 'AoN' || \
	  { echo "bench_defended: .note.aon missing from $@" >&2; rm -f $@; exit 1; }
	@echo "bench_defended: .note.aon present"

aon_syscalls.aon.o: $(AONLIBC)/aon_syscalls.S
	$(CC) $(ASFLAGS) -DAON_DEFEND -c $< -o $@

# ---- seccomp ------------------------------------------------------------
bench_seccomp: bench_seccomp.o aon_syscalls.o
	$(CC) $(LDFLAGS) -o $@ $^

bench_seccomp.o: bench.c
	$(CC) $(CFLAGS) -DBENCH_SECCOMP -c $< -o $@

bench_seccomp_ip: bench_seccomp_ip.o aon_syscalls.o
	$(CC) $(LDFLAGS) -o $@ $^

bench_seccomp_ip.o: bench.c
	$(CC) $(CFLAGS) -DBENCH_SECCOMP -DBENCH_SECCOMP_IP -c $< -o $@

clean:
	rm -f bench bench_defended bench_seccomp bench_seccomp_ip *.o
