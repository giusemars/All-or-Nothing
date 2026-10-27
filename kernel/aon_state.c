// SPDX-License-Identifier: GPL-2.0
/*
 * aon_state.c - the two pieces of state the AoN module keeps.
 *
 *   1. AoN regions: which address spaces (mm) have an AoN region, and where.
 *      Filled automatically at exec and inherited at fork (aon_lifecycle.c),
 *      dropped when the mm is torn down. There is no user-space interface to
 *      change it.
 *
 *   2. Armed state: one bit per thread (tid), set when the thread passes an
 *      ingress gate (the #UD handler), checked and cleared at the egress gate
 *      (the `syscall` check), so one ingress allows exactly one egress; also
 *      cleared before a signal handler is run and when the thread exits.
 *
 * Both are touched from probe/exception context, hence spinlocks with
 * irqsave and GFP_ATOMIC allocations.
 */
#include <linux/atomic.h>
#include <linux/hashtable.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

#include "aon.h"

/* ---- per-mm AoN regions ---------------------------------------------- */

#define AON_MAX_REGIONS 64

struct aon_region {
  struct mm_struct *mm; /* NULL = free slot */
  u64 start, end;       /* AoN region [start, end) */
};

static struct aon_region regions[AON_MAX_REGIONS];
static DEFINE_SPINLOCK(regions_lock);
static atomic_t nr_regions = ATOMIC_INIT(0);

static struct aon_region *region_find_locked(struct mm_struct *mm) {
  int i;

  for (i = 0; i < AON_MAX_REGIONS; i++)
    if (regions[i].mm == mm)
      return &regions[i];
  return NULL;
}

/* Set @mm's AoN region, taking a free slot if it has none yet. */
static int region_set_locked(struct mm_struct *mm, u64 start, u64 end) {
  struct aon_region *r = region_find_locked(mm);

  if (!r) {
    r = region_find_locked(NULL); /* free slot */
    if (!r)
      return -ENOSPC;
    atomic_inc(&nr_regions);
  }
  r->mm = mm;
  r->start = start;
  r->end = end;
  return 0;
}

int aon_region_add(struct mm_struct *mm, u64 start, u64 end) {
  unsigned long flags;
  int ret;

  spin_lock_irqsave(&regions_lock, flags);
  ret = region_set_locked(mm, start, end);
  spin_unlock_irqrestore(&regions_lock, flags);
  return ret;
}

int aon_region_copy(struct mm_struct *from, struct mm_struct *to) {
  struct aon_region *r;
  unsigned long flags;
  int ret = 0;

  spin_lock_irqsave(&regions_lock, flags);
  r = region_find_locked(from);
  if (r) /* the child's mm is a copy, so the same addresses apply */
    ret = region_set_locked(to, r->start, r->end);
  spin_unlock_irqrestore(&regions_lock, flags);
  return ret;
}

void aon_region_del(struct mm_struct *mm) {
  struct aon_region *r;
  unsigned long flags;

  if (!mm)
    return;
  spin_lock_irqsave(&regions_lock, flags);
  r = region_find_locked(mm);
  if (r) {
    r->mm = NULL;
    atomic_dec(&nr_regions);
  }
  spin_unlock_irqrestore(&regions_lock, flags);
}

enum aon_where aon_region_where(struct mm_struct *mm, u64 ip) {
  struct aon_region *r;
  unsigned long flags;
  enum aon_where where = AON_UNPROTECTED;

  if (!mm)
    return AON_UNPROTECTED;
  spin_lock_irqsave(&regions_lock, flags);
  r = region_find_locked(mm);
  if (r)
    where = (ip >= r->start && ip < r->end) ? AON_INSIDE : AON_OUTSIDE;
  spin_unlock_irqrestore(&regions_lock, flags);
  return where;
}

bool aon_region_contains(struct mm_struct *mm, u64 ip) {
  return aon_region_where(mm, ip) == AON_INSIDE;
}

bool aon_region_any(void) { return atomic_read(&nr_regions) > 0; }

/* ---- per-thread armed state (keyed by tid = task->pid) ---------------- */

struct aon_armed {
  struct hlist_node node;
  pid_t tid;
};

static DEFINE_HASHTABLE(armed_ht, 10);
static DEFINE_SPINLOCK(armed_lock);

static struct aon_armed *armed_find_locked(pid_t tid) {
  struct aon_armed *a;

  hash_for_each_possible(armed_ht, a, node, tid) if (a->tid == tid) return a;
  return NULL;
}

void aon_armed_set(pid_t tid) {
  struct aon_armed *a;
  unsigned long flags;

  spin_lock_irqsave(&armed_lock, flags);
  if (!armed_find_locked(tid)) {
    a = kmalloc(sizeof(*a), GFP_ATOMIC);
    if (a) {
      a->tid = tid;
      hash_add(armed_ht, &a->node, tid);
    }
  }
  spin_unlock_irqrestore(&armed_lock, flags);
}

bool aon_armed_test_and_clear(pid_t tid) {
  struct aon_armed *a;
  unsigned long flags;
  bool found = false;

  spin_lock_irqsave(&armed_lock, flags);
  a = armed_find_locked(tid);
  if (a) {
    hash_del(&a->node);
    kfree(a);
    found = true;
  }
  spin_unlock_irqrestore(&armed_lock, flags);
  return found;
}

void aon_armed_clear_all(void) {
  struct aon_armed *a;
  struct hlist_node *tmp;
  unsigned long flags;
  int bkt;

  spin_lock_irqsave(&armed_lock, flags);
  hash_for_each_safe(armed_ht, bkt, tmp, a, node) {
    hash_del(&a->node);
    kfree(a);
  }
  spin_unlock_irqrestore(&armed_lock, flags);
}
