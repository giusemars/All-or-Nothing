# glibc `cat` scenario for "All-or-Nothing Code Blocks".
#
# A minimal `cat` (open -> read loop -> write stdout -> close) built as an
# ordinary, dynamically linked glibc program -- unlike user/cat (nolibc,
# static, hardened library). No AoN mechanism, no -DAON_DEFEND variant, no
# kernel module: the plain-glibc "attacker wins" baseline. Invoked like
# `cat <filename>`; `aligned` / `misaligned` instead trigger vectors A / B,
# both reaching an execve (nr 59) the victim never invokes. Self-contained
# (cat.c/cat.h + the simulated primitives gadget.S / attacker.S).
#
# Target: x86_64, Linux (Debian 6.12), gcc + a stock glibc.
#
#   make        build ./cat
#   make run    seed victim.txt, run all modes
#   make clean

CC      := gcc

# -fcf-protection=none keeps CET endbr64 / shadow-stack markings out so the
# simulated hijack (an indirect jump onto a `syscall`) is not blocked by
# hardware CFI, per the PoC design. Ordinary dynamic glibc link (no -nostdlib /
# -static): read()/write()/... resolve to libc.so.6, where vector A's aligned
# `syscall` lives.
CFLAGS  := -O0 -g -Wall -Wextra -fcf-protection=none
ASFLAGS := -g

# ---- Baseline (attacker-wins) -------------------------------------------
cat: cat.o gadget.o attacker.o
	$(CC) -o $@ $^

cat.o: cat.c cat.h
	$(CC) $(CFLAGS) -c $< -o $@

# gadget.S / attacker.S are the simulated PoC primitives (local copies, so this
# scenario is self-contained).
gadget.o: gadget.S
	$(CC) $(ASFLAGS) -c $< -o $@

attacker.o: attacker.S
	$(CC) $(ASFLAGS) -c $< -o $@

# ---- Run / clean --------------------------------------------------------
# With no defense, aligned and misaligned both replace the process with
# /bin/echo (execve succeeds); the real filename mode cats the file.
.PHONY: run clean
run: cat
	./reset.sh
	@for m in victim.txt aligned misaligned; do \
	  echo "### baseline $$m ###"; ./cat $$m; echo "(exit $$?)"; \
	done

clean:
	rm -f cat cat.o gadget.o attacker.o victim.txt
