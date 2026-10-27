# aonlibc `signal` scenario for "All-or-Nothing Code Blocks".
#
# Isolates aon_mod's SIGNAL RULE (the kprobe on x64_setup_rt_frame: disarm the
# thread before a handler is run; the AoN rt_sigreturn restorer never re-arms
# it). Two reserved operands make the two points the `cat` scenario cannot:
#
#   sig correctness   a signal delivered while the thread is ARMED inside an
#                     AoN block refuses that block's egress gate; the caller
#                     executes the block again (availability cost of the rule);
#   sig attack-armed  a handler invoked while the thread is ARMED inside a
#                     block cannot ride that live arming into a reused
#                     `syscall`: the kernel disarms before the handler runs, so
#                     the reused egress gate is unarmed and is refused.
#   sig attack-unarmed  the same hijack from a handler invoked in ordinary code
#                     (thread never armed) -- the basic case, also refused.
#                     (security side of the rule). All modes use one mechanism
#                     -- a single-stepped `write` -- so there is no timer here.
#
# Self-contained like the other scenarios: it compiles the shared library
# sources (../../aonlibc) and the build tool (../../tools) directly, no sub-make.
# Only the simulated attacker primitive (attacker.S) is local; there is no
# misaligned-site gadget here (vector B is covered by the `cat` scenario).
#
# ONE aon_syscalls.S builds both variants, selected by -DAON_DEFEND:
#
#   sig           baseline / attacker-wins: plain mov/syscall/ret, no ingress
#                 gate, no .note.aon region. aon_mod does not intervene, so the
#                 handler's execve runs and the correctness demo has no arming
#                 to lose.
#   sig_defended  each wrapper becomes an AoN block with a `ud2` ingress gate;
#                 the linked blocks form the AoN region
#                 [__start_aon_text,__stop_aon_text), described by a .note.aon
#                 descriptor aon_mod reads at exec. verify_aon.py then proves
#                 the AoN region holds no stray ud2 besides the ingress gates,
#                 and readelf checks the note survived --gc-sections.
#
# sig.c never calls read(); the read wrapper (whose egress gate the attack
# reuses) is kept linked by the reference to sys_read_egress in sig.c.
#
#   make                build ./sig                 (baseline)
#   make run            run both baseline modes
#   make sig_defended   build ./sig_defended, then verify its AoN region
#   make defend-run     run both defended modes
#                       (needs aon_mod loaded: without it the ud2 is SIGILL)
#   make clean

CC      := gcc
AONLIBC := ../../aonlibc
NOLIBC  := $(AONLIBC)/nolibc
VERAON  := ../../tools/verify_aon.py

CFLAGS  := -O0 -g -Wall -Wextra -fno-pie -fcf-protection=none \
           -ffunction-sections -fdata-sections -I$(NOLIBC) -DNOLIBC_AON
ASFLAGS := -g
LDFLAGS := -nostdlib -static -no-pie -Wl,--gc-sections -Wl,-z,start-stop-gc

# ---- Baseline (attacker-wins) -------------------------------------------
sig: sig.o aon_syscalls.o attacker.o
	$(CC) $(LDFLAGS) -o $@ $^

sig.o: sig.c sig.h
	$(CC) $(CFLAGS) -c $< -o $@

aon_syscalls.o: $(AONLIBC)/aon_syscalls.S
	$(CC) $(ASFLAGS) -c $< -o $@

attacker.o: attacker.S
	$(CC) $(ASFLAGS) -c $< -o $@

# ---- Defended variant ---------------------------------------------------
sig_defended: sig.o aon_syscalls.aon.o attacker.o
	$(CC) $(LDFLAGS) -o $@ sig.o aon_syscalls.aon.o attacker.o
	$(VERAON) $@
	@readelf -n $@ | grep -q 'AoN' || \
	  { echo "sig_defended: .note.aon missing from $@" >&2; rm -f $@; exit 1; }
	@echo "sig_defended: .note.aon present"

aon_syscalls.aon.o: $(AONLIBC)/aon_syscalls.S
	$(CC) $(ASFLAGS) -DAON_DEFEND -c $< -o $@

# ---- Run / clean --------------------------------------------------------
# Baseline: both `attack-*` replace the process with /bin/echo (execve succeeds
# from the handler); `correctness` has no arming to lose, so the first write
# simply succeeds and the demo reports "not demonstrated".
# Defended (module loaded): both `attack-*` are blocked (exit 3, no execve) --
# attack-armed because the arming was disarmed before the handler ran,
# attack-unarmed because a handler is never armed -- and `correctness` shows the
# armed write refused once then recovered on retry.
.PHONY: run defend-run clean
run: sig
	@for m in correctness attack-armed attack-unarmed; do \
	  echo "### baseline $$m ###"; ./sig $$m; echo "(exit $$?)"; \
	done

defend-run: sig_defended
	@for m in correctness attack-armed attack-unarmed; do \
	  echo "### defended $$m ###"; ./sig_defended $$m; echo "(exit $$?)"; \
	done

clean:
	rm -f sig sig_defended sig.o aon_syscalls.o aon_syscalls.aon.o attacker.o
