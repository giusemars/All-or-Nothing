# "Bare syscall" glibc `cat` scenario for "All-or-Nothing Code Blocks".
#
# Same minimal `cat` (open -> read loop -> write stdout -> close) as the sibling
# `cat` scenario and still an ordinary, dynamically linked glibc program -- but
# the four file-I/O system calls are issued by the program's own bare `syscall`
# wrappers (syscalls.S) instead of glibc's read()/write()/open()/close(). So
# the aligned `syscall` reused by vector A lives in the program binary, not
# libc.so.6. No AoN mechanism, no -DAON_DEFEND variant, no kernel module: still
# the plain-glibc "attacker wins" baseline. Invoked like `cat_bare <filename>`;
# `aligned` / `misaligned` instead trigger vectors A / B, both reaching an
# execve (nr 59) the victim never invokes. Self-contained (cat.c/cat.h +
# syscalls.S + the simulated primitives gadget.S / attacker.S).
#
# Target: x86_64, Linux (Debian 6.12), gcc + a stock glibc.
#
#   make        build ./cat_bare
#   make run    seed victim.txt, run all modes
#   make clean

CC      := gcc

# -fcf-protection=none keeps CET endbr64 / shadow-stack markings out so the
# simulated hijack (an indirect jump onto a `syscall`) is not blocked by
# hardware CFI, per the PoC design. Ordinary dynamic glibc link (no -nostdlib /
# -static): fprintf()/strcmp() resolve to libc.so.6, while the file-I/O
# `syscall`s now live in the program's own syscalls.S.
CFLAGS  := -O0 -g -Wall -Wextra -fcf-protection=none
ASFLAGS := -g

# ---- Baseline (attacker-wins) -------------------------------------------
cat_bare: cat.o syscalls.o gadget.o attacker.o
	$(CC) -o $@ $^

cat.o: cat.c cat.h
	$(CC) $(CFLAGS) -c $< -o $@

# syscalls.S holds the bare direct-system-call wrappers (this scenario's
# distinguishing piece); gadget.S / attacker.S are the simulated PoC primitives
# (local copies, so this scenario is self-contained).
syscalls.o: syscalls.S
	$(CC) $(ASFLAGS) -c $< -o $@

gadget.o: gadget.S
	$(CC) $(ASFLAGS) -c $< -o $@

attacker.o: attacker.S
	$(CC) $(ASFLAGS) -c $< -o $@

# ---- Run / clean --------------------------------------------------------
# With no defense, aligned and misaligned both replace the process with
# /bin/echo (execve succeeds); the real filename mode cats the file.
.PHONY: run clean
run: cat_bare
	./reset.sh
	@for m in victim.txt aligned misaligned; do \
	  echo "### baseline $$m ###"; ./cat_bare $$m; echo "(exit $$?)"; \
	done

clean:
	rm -f cat_bare cat.o syscalls.o gadget.o attacker.o victim.txt
