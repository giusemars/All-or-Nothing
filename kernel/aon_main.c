// SPDX-License-Identifier: GPL-2.0
/*
 * aon_main.c - kernel enforcement for "All-or-Nothing Code Blocks" (PoC).
 *
 * Academic defensive-security PoC. No kernel patching and no user-space API:
 *
 *   - aon_lifecycle.c finds each exec'd program's AoN region by itself,
 *     from the AoN note in its ELF program headers, hands it down to
 *     forked children, and forgets it when the process exits;
 *   - aon_enforce.c arms a thread at a `ud2` ingress gate, checks and disarms
 *     it at a `syscall` egress gate, refuses an unarmed egress gate and any
 *     `syscall` outside the AoN region, and disarms a thread before a signal
 *     handler is run.
 *
 * Only programs exec'd AFTER the module is loaded are protected.
 */
#include <linux/init.h>
#include <linux/module.h>

#include "aon.h"

static int __init aon_init(void) {
  int ret;

  /* Enforcement first, so an AoN region is never recorded without its
   * checks. */
  ret = aon_enforce_init();
  if (ret)
    return ret;

  ret = aon_lifecycle_init();
  if (ret) {
    aon_enforce_exit();
    return ret;
  }

  pr_info("aon: loaded (looking for the \"%s\" ELF note at exec)\n",
          AON_NOTE_NAME);
  return 0;
}

static void __exit aon_exit(void) {
  aon_lifecycle_exit();
  aon_enforce_exit();
  aon_armed_clear_all();
  pr_info("aon: unloaded\n");
}

module_init(aon_init);
module_exit(aon_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("All-or-Nothing PoC");
MODULE_DESCRIPTION("All-or-Nothing block enforcement: AoN regions found at "
                   "exec from an ELF note, ud2 ingress gate + syscall egress "
                   "gate");
