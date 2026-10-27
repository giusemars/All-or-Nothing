// SPDX-License-Identifier: GPL-2.0
/*
 * aon_enforce.c - kernel enforcement of the All-or-Nothing blocks.
 *
 * The kernel observes only the two gates of each AoN block:
 *
 *   INGRESS GATE (register_die_notifier): the `ud2` ingress gate raises #UD
 *     (a fault). On DIE_TRAP/X86_TRAP_UD from user mode with RIP inside the
 *     process's AoN region, ARM the current thread, step RIP past the 2-byte
 *     `ud2`, and return NOTIFY_STOP so no SIGILL is delivered -- a
 *     user-transparent kernel entry: execution resumes at the first
 *     instruction of the body.
 *
 *   EGRESS GATE (kprobe on x64_sys_call, the common 64-bit system call
 *     dispatch): for a process that has an AoN region, every `syscall` is
 *     checked by the address of the `syscall` instruction itself -- the
 *     egress gate of the block (design property B3) -- which is the saved
 *     user RIP minus its 2 bytes:
 *
 *       inside the AoN region,  armed      -> disarm and allow;
 *       inside the AoN region,  not armed  -> unarmed egress gate: the thread
 *                                             never passed the ingress gate
 *                                             (vector A): refuse (property A2);
 *       outside the AoN region             -> not an egress gate at all
 *                                             (vector B, the vDSO, any stray
 *                                             `0f 05`): refuse (property B1).
 *
 *     Processes without an AoN region are never touched.
 *
 *   SIGNAL RULE (kprobe on x64_setup_rt_frame): when the kernel is about to
 *     run a handler for an armed thread, it DISARMS the thread; rt_sigreturn
 *     never re-arms it. This stops the arming from leaking into the handler,
 *     and a forged signal frame can only resume a disarmed thread, whose
 *     egress gate is refused. Cost: the egress gate of the interrupted block
 *     fails, and the caller has to execute the block again.
 *
 * Why observing only the gates is enough: the body contains no explicit
 * control transfer (static condition), and no implicit control transfer lets
 * an armed thread continue in user space at another instruction or with
 * another register state (dynamic condition, ensured by the signal rule).
 * The coarse "RIP in AoN region" test at the ingress gate is sound only
 * because the build-time verifier (verify_ud2) proves the AoN region has no
 * stray 0f 0b besides the ingress gates.
 */
#include <asm/trapnr.h>
#include <linux/kdebug.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/notifier.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/sched/task_stack.h>
#include <linux/signal.h>
#include <linux/sysfs.h>

#include "aon.h"

/* How to refuse a system call (unarmed egress gate, or a `syscall` outside
 * the AoN region):
 *   1 = rewrite the system call nr arg (RSI) to an invalid number, so the
 *       dispatch returns -ENOSYS. Register-only, honored by both int3- and
 *       ftrace-based kprobes -- the safe DEFAULT.
 *   0 = return -EACCES by skipping the function body of x64_sys_call (pop its
 *       return address into RIP, set RAX). Relies on the stack layout at the
 *       probe point; verify it is stable on your kernel before relying on it.
 * Both modes equally prevent the effect of the system call. */
static int neutralize_mode = 1;
module_param(neutralize_mode, int, 0644);
MODULE_PARM_DESC(neutralize_mode, "1=block via -ENOSYS nr override (default, "
                                  "safe); 0=block via -EACCES return skip");

/* ---- INGRESS GATE: #UD die-notifier --------------------------------- */

static int aon_die(struct notifier_block *nb, unsigned long val, void *data) {
  struct die_args *args = data;
  struct pt_regs *regs = args->regs;
  u64 ip;

  if (!aon_region_any())
    return NOTIFY_DONE;
  if (val != DIE_TRAP || args->trapnr != X86_TRAP_UD)
    return NOTIFY_DONE;
  if (!user_mode(regs))
    return NOTIFY_DONE;

  ip = instruction_pointer(regs);
  if (!aon_region_contains(current->mm, ip))
    return NOTIFY_DONE; /* any other #UD: let SIGILL happen */

  /* Ingress gate: arm, skip the 2-byte ud2, swallow the fault. */
  aon_armed_set(current->pid);
  instruction_pointer_set(regs, ip + 2);
  return NOTIFY_STOP;
}

static struct notifier_block aon_die_nb = {
    .notifier_call = aon_die,
};

/* ---- EGRESS GATE: system call dispatch kprobe ----------------------- */

/* Size of the `syscall` instruction (0f 05): the saved user RIP minus this is
 * the address of the `syscall` that entered the kernel. */
#define AON_SYSCALL_INSN_LEN 2

static int aon_syscall_pre(struct kprobe *p, struct pt_regs *regs) {
  u64 insn;
  const char *why;

  if (!aon_region_any())
    return 0;

  /* The user RIP saved at the kernel entry is the instruction after the
   * `syscall`. */
  insn = instruction_pointer(task_pt_regs(current)) - AON_SYSCALL_INSN_LEN;

  switch (aon_region_where(current->mm, insn)) {
  case AON_UNPROTECTED:
    return 0; /* an ordinary program: not ours to police */
  case AON_INSIDE:
    if (aon_armed_test_and_clear(current->pid))
      return 0; /* egress gate reached through its ingress gate: allow */
    why = "unarmed egress gate"; /* vector A (A2) */
    break;
  case AON_OUTSIDE:
  default:
    why = "outside the AoN region"; /* vector B, vDSO, stray bytes (B1) */
    break;
  }

  pr_warn_ratelimited(
      "aon: BLOCKED system call nr=%lu at syscall 0x%llx (%s) (pid=%d "
      "comm=%s)\n",
      (unsigned long)regs->si, insn, why, current->pid, current->comm);

  if (neutralize_mode == 0) {
    /* Make x64_sys_call "return" -EACCES without running it. */
    regs->ax = (unsigned long)(-EACCES);
    regs->ip = *(unsigned long *)regs->sp;
    regs->sp += sizeof(long);
    return 1; /* we changed RIP; skip the original */
  }

  /* Default: rewrite nr (2nd arg, RSI) so the dispatch returns -ENOSYS. */
  regs->si = 0xffffffffUL;
  return 0;
}

static struct kprobe aon_syscall_kp = {
    .symbol_name = "x64_sys_call",
    .pre_handler = aon_syscall_pre,
};

/* ---- SIGNAL RULE: disarm before a handler is run -------------------- */

/* The x86 handle_signal() (static, inlined into arch_do_signal_or_restart)
 * builds a 64-bit handler's frame through x64_setup_rt_frame(ksig, regs), and
 * only once get_signal() has chosen a user handler: never for SIG_IGN, default
 * actions, or a signal a tracer swallowed. It runs in the receiving thread on
 * its way back to user mode, before the frame is written, so the user RIP in
 * task_pt_regs(current) is still the interrupted one.
 *
 * NOT IMPLEMENTED in this PoC: ia32/x32 frames (ia32_setup_rt_frame,
 * ia32_setup_frame, x32_setup_rt_frame). A handler only gets one if it was
 * installed by an rt_sigaction invoked through a compat entry (int $0x80, or
 * a `syscall` with __X32_SYSCALL_BIT), and those kernel entries are not
 * policed either (they bypass x64_sys_call, the only one the egress gate
 * kprobe observes). exec resets all handlers, so a protected program starts
 * without any. */
static atomic_long_t aon_signal_disarms = ATOMIC_LONG_INIT(0);

static int signal_disarms_get(char *buf, const struct kernel_param *kp) {
  return sysfs_emit(buf, "%ld\n", atomic_long_read(&aon_signal_disarms));
}
static const struct kernel_param_ops signal_disarms_ops = {
    .get = signal_disarms_get,
};
module_param_cb(signal_disarms, &signal_disarms_ops, NULL, 0444);
MODULE_PARM_DESC(signal_disarms, "threads disarmed at signal delivery so far");

static int aon_sigframe_pre(struct kprobe *p, struct pt_regs *regs) {
  struct ksignal *ksig = (struct ksignal *)regs_get_kernel_argument(regs, 0);

  if (!aon_region_any())
    return 0;
  /* Probe context: cannot sleep; the armed table's irqsave spinlock is the
   * same one the egress gate kprobe takes. */
  if (!aon_armed_test_and_clear(current->pid))
    return 0;

  atomic_long_inc(&aon_signal_disarms);
  pr_info_ratelimited("aon: DISARMED at signal %d delivery, interrupted at "
                      "0x%lx (%s) (pid=%d comm=%s)\n",
                      ksig->sig, instruction_pointer(task_pt_regs(current)),
                      p->symbol_name, current->pid, current->comm);
  return 0;
}

static struct kprobe aon_sigframe_kp = {
    .symbol_name = "x64_setup_rt_frame",
    .pre_handler = aon_sigframe_pre,
};

/* ---- registration ---------------------------------------------------- */

int aon_enforce_init(void) {
  int ret;

  ret = register_die_notifier(&aon_die_nb);
  if (ret)
    return ret;

  ret = register_kprobe(&aon_syscall_kp);
  if (ret) {
    pr_err("aon: register_kprobe(%s) failed: %d\n", aon_syscall_kp.symbol_name,
           ret);
    unregister_die_notifier(&aon_die_nb);
    return ret;
  }

  ret = register_kprobe(&aon_sigframe_kp);
  if (ret) {
    pr_err("aon: register_kprobe(%s) failed: %d\n",
           aon_sigframe_kp.symbol_name, ret);
    unregister_kprobe(&aon_syscall_kp);
    unregister_die_notifier(&aon_die_nb);
    return ret;
  }
  return 0;
}

void aon_enforce_exit(void) {
  unregister_kprobe(&aon_sigframe_kp);
  unregister_kprobe(&aon_syscall_kp);
  unregister_die_notifier(&aon_die_nb);
}
