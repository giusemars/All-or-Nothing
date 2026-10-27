/*
 * sig.c - aonlibc `signal` victim + driver for the All-or-Nothing Code Blocks
 *         proof of concept.
 *
 * This scenario is about one thing: aon_mod's SIGNAL RULE (the kprobe on
 * x64_setup_rt_frame -- disarm the thread before a handler is run; the AoN
 * rt_sigreturn restorer never re-arms it). Two reserved operands make the two
 * points the `cat` scenario cannot:
 *
 *   sig correctness   availability side of the rule. A SIGTRAP is delivered
 *                     to the thread while it is ARMED inside the `write` AoN
 *                     block (we single-step into the block, so the trap lands
 *                     on its egress gate deterministically). The kernel
 *                     disarms before running the handler, so when the thread
 *                     resumes onto the `syscall` it is an unarmed egress gate
 *                     and is refused (-ENOSYS). The caller executes the block
 *                     again and it succeeds. -- Meaningful only on the
 *                     defended build with aon_mod loaded; the baseline has no
 *                     arming to lose, so the first write simply succeeds.
 *
 *   sig attack-armed  security side, the stronger case: a handler is invoked
 *                     WHILE THE THREAD IS ARMED inside an AoN block (we
 *                     single-step a `write`, so the handler fires on its egress
 *                     gate) and from there reuses the read wrapper's egress
 *                     gate for execve (nr 59). The victim's live arming does
 *                     not leak into the handler -- the kernel disarms before
 *                     running it and rt_sigreturn never re-arms -- so the
 *                     reused egress gate is unarmed and refused.
 *
 *   sig attack-unarmed  security side, the basic case: the same hijack, but
 *                     from a handler invoked while the thread is in ORDINARY
 *                     CODE (not in any AoN block, so never armed). A handler is
 *                     never armed to begin with, so the reused egress gate is
 *                     unarmed and refused.
 *
 * In both attack cases the defended build refuses the execve and control
 * returns (exit 3); the baseline runs it (/bin/echo replaces the process --
 * attacker wins).
 *
 * The attacker's capabilities are SIMULATED (attacker.S). execve (nr 59) is
 * not an intended system call of this program: the only way to invoke it is by
 * reusing a `syscall`, which is the point of the thesis.
 *
 * Build & run: see Makefile.  Usage: ./sig <correctness|attack-armed|attack-unarmed>
 */
#include "nolibc.h"
#include "sig.h"

/* execve payload. Harmless and observable: on a successful hijack /bin/echo
 * replaces the process image, prints this line and exits. No network, no
 * privileged action -- it only demonstrates that control reached an execve the
 * victim never intended to invoke. */
static char *const EVIL_ARGV[] = {
	"/bin/echo",
	"[attacker] execve() hijack from a signal handler succeeded",
	0,
};
static char *const EVIL_ENVP[] = { 0 };

/* Kernel ABI constants and layouts (nolibc 6.12 ships neither). */
#define T_SIGTRAP	5
#define T_SA_SIGINFO	0x00000004UL
#define T_SA_RESTORER	0x04000000UL
#define T_SA_NODEFER	0x40000000UL
#define T_ENOSYS	38
#define T_TF		0x100UL		/* EFLAGS.TF: single-step */
/* offsetof(ucontext_t, uc_mcontext.gregs[REG_RIP / REG_EFL]) on x86_64 */
#define UC_RIP		168
#define UC_EFL		176
/* The two bytes of a `syscall` instruction (0f 05), little-endian. */
#define SYSCALL_BYTES	0x050f

struct t_sigaction {
	void		*handler;
	unsigned long	 flags;
	void		*restorer;
	unsigned long	 mask;		/* 64 signals */
};

/* ../../aonlibc/aon_syscalls.S: the signal wrappers (not part of nolibc's API)
 * and the ingress gate of the write block we single-step through. */
long sys_rt_sigaction(int sig, const struct t_sigaction *act,
		      struct t_sigaction *oact, size_t sigsetsize);
void sys_rt_sigreturn(void);
extern char __aon_write[];

static unsigned long uc_rip(void *uc)
{
	return *(unsigned long *)((char *)uc + UC_RIP);
}
static unsigned long *uc_eflags(void *uc)
{
	return (unsigned long *)((char *)uc + UC_EFL);
}
static void set_tf(void)
{
	__asm__ volatile("pushfq; orq $0x100, (%%rsp); popfq" ::: "memory", "cc");
}

/* argv parsing with no system call (keeps the victim's system calls to
 * exactly its intended ones). */
static int streq(const char *a, const char *b)
{
	while (*a && *a == *b) {
		a++;
		b++;
	}
	return *a == *b;
}

/* Install @handler for @sig with the AoN rt_sigreturn restorer. No async
 * signal can arrive during setup (no timer is armed yet), so no retry is
 * needed here. */
static void install(int sig, void *handler, unsigned long flags)
{
	struct t_sigaction a = { handler, flags | T_SA_RESTORER,
				 sys_rt_sigreturn, 0 };
	if (sys_rt_sigaction(sig, &a, 0, 8)) {
		write(2, "sig: rt_sigaction failed\n", 25);
		sys_exit(2);
	}
}

/* ---- the shared single-step mechanism ----------------------------------
 * Both modes drive a signal into the thread WHILE IT IS ARMED inside an AoN
 * block, by single-stepping a protected `write`. EFLAGS.TF makes the CPU
 * raise a #DB (delivered as SIGTRAP) after each instruction, so a SIGTRAP is
 * guaranteed to land on the write block's `syscall` -- its egress gate -- with
 * the thread armed. Before running the handler the kernel's signal rule
 * disarms the thread; the handler then either
 *
 *   correctness (attack_mode = 0)  does nothing. The interrupted `write`
 *       resumes onto an unarmed egress gate and is refused, so the caller runs
 *       the block again -- the availability cost of the rule.
 *
 *   attack-armed   (HIJACK_ARMED)  reuses the READ egress gate for execve (nr
 *       59) from inside the handler. The thread is no longer armed (the signal
 *       rule spent its arming at delivery, and rt_sigreturn never re-arms), so
 *       the reused egress gate is unarmed and is refused: the victim's live
 *       arming did NOT leak into the attacker's handler.
 *
 *   attack-unarmed (HIJACK_UNARMED)  the same hijack, but done from the FIRST
 *       single-step trap -- which lands while RIP is still in ordinary code,
 *       before any ingress gate, so the thread is not armed. A handler is never
 *       armed, so the reused egress gate is unarmed and is refused. (This case
 *       needs no armed window, so it fires on the first trap instead of
 *       stepping into the block.) */
enum handler_action {
	HANDLER_NOOP,		/* correctness: let the interrupted block fail */
	HIJACK_ARMED,		/* attack-armed:   hijack at the armed egress gate */
	HIJACK_UNARMED,		/* attack-unarmed: hijack from ordinary code */
};
static volatile int handler_action;
static volatile int handler_fired;	/* the handler ran and attempted its job */

static void do_hijack(void)
{
	hijack((void *)sys_read_egress, 59,
	       (long)EVIL_ARGV[0], (long)EVIL_ARGV, (long)EVIL_ENVP);
	/* defended: the execve was refused and control returned here; baseline:
	 * the execve already replaced the process and this never returns. */
}

static void on_trap(int sig, void *info, void *uc)
{
	unsigned long rip = uc_rip(uc);

	(void)sig;
	(void)info;

	if (handler_action == HIJACK_UNARMED) {
		/* The first trap lands with RIP in ordinary code and the thread
		 * NOT armed (no ingress gate crossed yet). Hijack from here and
		 * stop stepping. */
		*uc_eflags(uc) &= ~T_TF;
		handler_fired = 1;
		do_hijack();
		return;
	}

	/* HANDLER_NOOP / HIJACK_ARMED: keep single-stepping until RIP sits on
	 * the write block's `syscall` -- its egress gate -- with the thread
	 * armed (matched by opcode, so it holds in both builds despite the
	 * 2-byte ingress-gate shift). By the time this trap lands there, the
	 * kernel has already disarmed the thread. */
	if (rip - (unsigned long)__aon_write < 16 &&
	    *(unsigned short *)rip == SYSCALL_BYTES) {
		*uc_eflags(uc) &= ~T_TF;	/* stop stepping */
		handler_fired = 1;
		if (handler_action == HIJACK_ARMED)
			do_hijack();
	}
}

/* ---- correctness: a signal while armed refuses the egress -------------- */
static int run_correctness(void)
{
	static const char probe[] = "correctness: the single-stepped write\n";
	long r1, r2 = 0;

	handler_action = HANDLER_NOOP;
	install(T_SIGTRAP, on_trap, T_SA_SIGINFO | T_SA_NODEFER);

	/* sys_write is the raw wrapper (returns the kernel value, no errno
	 * translation), so a refused egress shows as -ENOSYS directly. */
	set_tf();
	r1 = sys_write(1, probe, sizeof(probe) - 1);

	if (r1 == -T_ENOSYS)
		r2 = sys_write(1, probe, sizeof(probe) - 1);	/* retry */

	fprintf(stderr, "sig correctness:\n");
	fprintf(stderr, "  write #1 = %ld%s\n", r1,
		r1 == -T_ENOSYS ? "  (-ENOSYS: egress refused -- a signal ran "
				  "while the thread was armed)"
				: "  (allowed)");
	if (r1 == -T_ENOSYS) {
		fprintf(stderr, "  write #2 = %ld  (the block was executed "
				"again -- recovered)\n", r2);
		fprintf(stderr, "sig correctness: OK -- signal while armed -> "
				"egress refused -> retry succeeds\n");
		return r2 < 0 ? 1 : 0;
	}
	fprintf(stderr, "sig correctness: not demonstrated -- needs the "
			"defended build with aon_mod loaded\n");
	return 1;
}

/* ---- attack: a handler cannot invoke execve, armed interrupt or not ----
 * @armed selects which case: the handler fires on the write block's egress
 * gate with the thread armed (HIJACK_ARMED), or on the first trap in ordinary
 * code with the thread unarmed (HIJACK_UNARMED). Either way the reused read
 * egress gate is unarmed when the handler hits it, so execve is refused. */
static int run_attack(int armed)
{
	static const char carrier[] = "attack: single-stepped carrier write\n";

	handler_action = armed ? HIJACK_ARMED : HIJACK_UNARMED;
	install(T_SIGTRAP, on_trap, T_SA_SIGINFO | T_SA_NODEFER);

	/* set_tf() + a protected write: the first trap (ordinary code, unarmed)
	 * drives the unarmed case; stepping on into the block drives the armed
	 * case. On the baseline the handler's execve replaces the process
	 * (attacker wins) and we never return; on the defended build it is
	 * refused and control comes back here. */
	set_tf();
	sys_write(1, carrier, sizeof(carrier) - 1);

	if (!handler_fired) {
		fprintf(stderr, "sig attack: handler never fired -- "
				"inconclusive (needs the defended build with "
				"aon_mod loaded)\n");
		return 1;
	}
	if (armed)
		fprintf(stderr,
			"sig attack-armed: a handler ran while the thread was "
			"ARMED inside the write block and reused the read "
			"egress gate for execve -- refused.\n  the victim's "
			"arming did not leak into the handler; exit 3\n");
	else
		fprintf(stderr,
			"sig attack-unarmed: a handler ran while the thread was "
			"in ordinary code (not in an AoN block, unarmed) and "
			"reused the read egress gate for execve -- refused.\n  "
			"a handler is never armed, so the egress gate is "
			"unarmed; exit 3\n");
	return 3;
}

int main(int argc, char **argv)
{
	static const char usage[] =
		"usage: sig <correctness|attack-armed|attack-unarmed>\n";

	if (argc >= 2 && streq(argv[1], "correctness"))
		return run_correctness();
	if (argc >= 2 && streq(argv[1], "attack-armed"))
		return run_attack(1);
	if (argc >= 2 && streq(argv[1], "attack-unarmed"))
		return run_attack(0);

	write(2, usage, sizeof(usage) - 1);
	return 1;
}
