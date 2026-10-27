// SPDX-License-Identifier: GPL-2.0
/*
 * aon_lifecycle.c - AoN region discovery at exec, inheritance at fork,
 *                   cleanup at exit.
 *
 * No user-space registration: the kernel itself decides which range of a
 * process is its AoN region, from the executable that was exec'd.
 *
 * EXEC  kprobe on finalize_exec(bprm) -- the new mm is fully built, but no
 *       user instruction of the new image has run yet. A probe handler cannot
 *       sleep (and reading user memory may), so it only queues a task_work.
 *       The task_work runs in process context on the way back to user space --
 *       still before the first user instruction -- and there we read the AoN
 *       note from the new image (aon_elf.c) and record its AoN region for
 *       the mm.
 *
 * FORK  kprobe on wake_up_new_task(child) -- called once fork has succeeded,
 *       before the child runs its first instruction. A forked child's mm is a
 *       copy of the parent's (current->mm), so it gets the same AoN region.
 *       Threads and vfork children (CLONE_VM) share the parent's mm: nothing
 *       to copy.
 *       (dup_mm/dup_mmap would be the natural hook, but they are inlined into
 *       copy_process and cannot be probed.)
 *
 * EXIT  kprobe on exit_mmap(mm) -- the address space is being torn down (last
 *       user gone: process exit, or the old mm being replaced by an exec), so
 *       its AoN region is dropped before the mm can be freed and its pointer
 *       reused. kprobe on do_exit() clears the exiting thread's armed state so
 *       a recycled tid can never inherit it.
 *
 * Fail-closed: if a binary carries the AoN note but its AoN region cannot be
 * recorded, nothing arms its threads and the #UD fault of its first ingress
 * gate is delivered as SIGILL.
 */
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/slab.h>
#include <linux/task_work.h>

#include "aon.h"

/* ---- EXEC ------------------------------------------------------------ */

/* Runs in the exec'ing task, in process context, before it returns to user. */
static void aon_exec_scan(struct callback_head *cb) {
  struct mm_struct *mm = current->mm;
  u64 start, end;
  int ret;

  if (!mm) /* exec failed after the point of no return; task is dying */
    goto out;

  ret = aon_elf_find_region(mm, &start, &end);
  if (ret) {
    if (ret != -ENOENT && ret != -ENOEXEC)
      pr_warn("aon: pid=%d comm=%s: cannot read the AoN note (%d)\n",
              current->pid, current->comm, ret);
    goto out; /* no AoN region: an ordinary program */
  }

  ret = aon_region_add(mm, start, end);
  if (ret)
    pr_warn("aon: pid=%d comm=%s: AoN region NOT recorded (%d)\n",
            current->pid, current->comm, ret);
  else
    pr_info("aon: pid=%d comm=%s: protecting [0x%llx, 0x%llx)\n",
            current->pid, current->comm, start, end);

out:
  kfree(cb);
  module_put(THIS_MODULE); /* pairs with try_module_get() at queue time */
}

static int aon_exec_pre(struct kprobe *p, struct pt_regs *regs) {
  struct callback_head *cb;

  /* Keep the module alive until the queued callback has run. */
  if (!try_module_get(THIS_MODULE))
    return 0;

  cb = kmalloc(sizeof(*cb), GFP_ATOMIC);
  if (!cb)
    goto fail;
  init_task_work(cb, aon_exec_scan);

  if (task_work_add(current, cb, TWA_RESUME)) {
    kfree(cb); /* task is already exiting */
    goto fail;
  }
  return 0;

fail:
  module_put(THIS_MODULE);
  return 0;
}

/* ---- FORK ------------------------------------------------------------ */

static int aon_fork_pre(struct kprobe *p, struct pt_regs *regs) {
  struct task_struct *child =
      (struct task_struct *)regs_get_kernel_argument(regs, 0);
  struct mm_struct *parent_mm = current->mm;

  if (!aon_region_any())
    return 0;
  if (!child->mm || child->mm == parent_mm) /* kthread, thread or vfork */
    return 0;

  if (aon_region_copy(parent_mm, child->mm))
    pr_warn("aon: fork pid=%d -> %d: AoN region NOT copied (table full)\n",
            current->pid, child->pid);
  return 0;
}

/* ---- EXIT ------------------------------------------------------------ */

static int aon_exit_mmap_pre(struct kprobe *p, struct pt_regs *regs) {
  if (aon_region_any())
    aon_region_del((struct mm_struct *)regs_get_kernel_argument(regs, 0));
  return 0;
}

static int aon_do_exit_pre(struct kprobe *p, struct pt_regs *regs) {
  if (aon_region_any())
    aon_armed_test_and_clear(current->pid);
  return 0;
}

/* ---- registration ---------------------------------------------------- */

static struct kprobe aon_exec_kp = {
    .symbol_name = "finalize_exec",
    .pre_handler = aon_exec_pre,
};
static struct kprobe aon_fork_kp = {
    .symbol_name = "wake_up_new_task",
    .pre_handler = aon_fork_pre,
};
static struct kprobe aon_exit_mmap_kp = {
    .symbol_name = "exit_mmap",
    .pre_handler = aon_exit_mmap_pre,
};
static struct kprobe aon_do_exit_kp = {
    .symbol_name = "do_exit",
    .pre_handler = aon_do_exit_pre,
};

static struct kprobe *aon_lifecycle_kps[] = {
    &aon_exec_kp,
    &aon_fork_kp,
    &aon_exit_mmap_kp,
    &aon_do_exit_kp,
};

int aon_lifecycle_init(void) {
  int ret = register_kprobes(aon_lifecycle_kps, ARRAY_SIZE(aon_lifecycle_kps));

  if (ret)
    pr_err("aon: exec/fork/exit kprobes failed: %d\n", ret);
  return ret;
}

void aon_lifecycle_exit(void) {
  unregister_kprobes(aon_lifecycle_kps, ARRAY_SIZE(aon_lifecycle_kps));
}
