# aonlibc `cat` scenario for "All-or-Nothing Code Blocks".
#
# A minimal `cat` (open -> read loop -> write stdout -> close) linked
# -nostdlib -static against the hardened syscall library in ../../aonlibc (the
# vendored nolibc and the hardened named wrappers in aon_syscalls.S). Every
# system call goes through those wrappers -- its INTENDED system calls (open,
# read, write, close, exit). Invoked like `cat <filename>`; two reserved
# operands select the attack methodology: `aligned` jumps onto the egress gate
# of the read wrapper (an aligned gadget), `misaligned` jumps onto the
# misaligned site in gadget.S, any other operand is catted for real. The
# attacker's goal is an `execve` (nr 59), not an intended system call: the
# victim never invokes it itself.
#
# Scenario-local: the victim (cat.c/cat.h) and the simulated attacker primitives
# (gadget.S / attacker.S) live here; the reusable syscall library is sourced
# from ../../aonlibc and the build tool from ../../tools. This Makefile is still
# self-contained -- it compiles the library sources directly, with no sub-make.
#
# ONE aon_syscalls.S (in ../../aonlibc) builds both variants, selected by
# -DAON_DEFEND:
#
#   cat           baseline / attacker-wins: the wrappers are plain
#                 mov/syscall/ret with no ingress gate and no .note.aon region.
#   cat_defended  the same program whose wrappers become AoN blocks with a
#                 `ud2` ingress gate, plus a .note.aon descriptor of the AoN
#                 region [__start_aon_text,__stop_aon_text) that aon_mod reads
#                 at exec. After linking, verify_aon.sh proves the AoN region
#                 holds no stray ud2 besides the ingress gates, and readelf
#                 checks the note survived --gc-sections.
#
# cat.c is compiled with -DNOLIBC_AON in BOTH builds so sys.h declares
# sys_open/read/write/close/exit extern and they link against aon_syscalls.o;
# this gives a stable egress gate symbol (sys_read_egress) for the attack in
# the baseline too.
#
# Target: x86_64, Linux (Debian 6.12), gcc. nolibc is vendored (from Linux
# v6.12 tools/include/nolibc), so no toolchain beyond a plain gcc is required.
#
#   make                 build ./cat                 (baseline)
#   make run             seed victim.txt, run all baseline modes
#   make cat_defended    build ./cat_defended, then verify its AoN region
#   make defend-run      seed victim.txt, run all defended modes
#                        (needs aon_mod loaded: without it the ud2 is SIGILL)
#   make clean

CC      := gcc
AONLIBC := ../../aonlibc
NOLIBC  := $(AONLIBC)/nolibc
VERIFY  := ../../tools/verify_ud2
VERAON  := ../../tools/verify_aon.sh

# Compile: -fno-pie fixes the load address (paired with -no-pie at link);
# -fcf-protection=none keeps CET endbr64/shadow-stack markings out of cat.o;
# -I$(NOLIBC) finds the vendored headers; -DNOLIBC_AON makes sys.h declare the
# five sys_* wrappers extern (defined in aonlibc/aon_syscalls.S). Each
# function/datum goes in its own section so --gc-sections can drop the unused
# nolibc functions without changing the -O0 codegen of the survivors.
CFLAGS  := -O0 -g -Wall -Wextra -fno-pie -fcf-protection=none \
           -ffunction-sections -fdata-sections -I$(NOLIBC) -DNOLIBC_AON
ASFLAGS := -g

# Link: -nostdlib -static links nolibc's tiny startup (and nothing else).
# --gc-sections -z start-stop-gc includes only the wrappers of the required
# system calls: each AoN block is its own `aon_text` input section, and
# start-stop-gc stops the note's __start_/__stop_aon_text reference from
# keeping all of them (see ../../aonlibc/aon_syscalls.S). cat requires all five
# file I/O + exit wrappers and none of the signal ones.
LDFLAGS := -nostdlib -static -no-pie -Wl,--gc-sections -Wl,-z,start-stop-gc

# ---- Baseline (attacker-wins) -------------------------------------------
cat: cat.o aon_syscalls.o gadget.o attacker.o
	$(CC) $(LDFLAGS) -o $@ $^

cat.o: cat.c cat.h
	$(CC) $(CFLAGS) -c $< -o $@

aon_syscalls.o: $(AONLIBC)/aon_syscalls.S
	$(CC) $(ASFLAGS) -c $< -o $@

# gadget.S / attacker.S are the simulated PoC primitives (local copies, so this
# scenario is self-contained and can seed others without any sibling user* dir).
gadget.o: gadget.S
	$(CC) $(ASFLAGS) -c $< -o $@

attacker.o: attacker.S
	$(CC) $(ASFLAGS) -c $< -o $@

# ---- Defended variant ---------------------------------------------------
# Same cat.o / gadget.o / attacker.o; aon_syscalls is rebuilt with -DAON_DEFEND
# so each wrapper gains its `ud2` ingress gate and the .note.aon descriptor is
# emitted. verify_aon.sh then proves the only ud2 in the AoN region
# [__start_aon_text,__stop_aon_text) are the declared ingress gates, and
# readelf checks the .note.aon descriptor survived --gc-sections.
cat_defended: cat.o aon_syscalls.aon.o gadget.o attacker.o $(VERIFY)
	$(CC) $(LDFLAGS) -o $@ cat.o aon_syscalls.aon.o gadget.o attacker.o
	$(VERAON) $@
	@readelf -n $@ | grep -q 'AoN' || \
	  { echo "cat_defended: .note.aon missing from $@" >&2; rm -f $@; exit 1; }
	@echo "cat_defended: .note.aon present"

aon_syscalls.aon.o: $(AONLIBC)/aon_syscalls.S
	$(CC) $(ASFLAGS) -DAON_DEFEND -c $< -o $@

$(VERIFY): $(VERIFY).c
	$(CC) -O2 -Wall -Wextra -o $@ $<

# ---- Run / clean --------------------------------------------------------
# Baseline: aligned and misaligned both replace the process with /bin/echo
# (execve succeeds). Defended (module loaded): aon_mod blocks both (the execve
# never runs, control returns, exit 3) -- aligned because the thread never
# passed the ingress gate (unarmed egress gate), misaligned because its
# `syscall` is outside the AoN region.
.PHONY: run defend-run clean
run: cat
	./reset.sh
	@for m in victim.txt aligned misaligned; do \
	  echo "### baseline $$m ###"; ./cat $$m; echo "(exit $$?)"; \
	done

defend-run: cat_defended
	./reset.sh
	@for m in victim.txt aligned misaligned; do \
	  echo "### defended $$m ###"; ./cat_defended $$m; echo "(exit $$?)"; \
	done

clean:
	rm -f cat cat_defended cat.o aon_syscalls.o aon_syscalls.aon.o \
	      gadget.o attacker.o victim.txt
