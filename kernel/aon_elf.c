// SPDX-License-Identifier: GPL-2.0
/*
 * aon_elf.c - locate a process's AoN region from the ELF note it carries.
 *
 * A protected program carries one ELF note (see aonlibc/aon_syscalls.S):
 *
 *   owner AON_NOTE_NAME, type NT_AON_REGION,
 *   descriptor = { s32 __start_aon_text - desc, s32 __stop_aon_text - desc }
 *
 * The bounds are the ones ld generates around the `aon_text` output section,
 * which gathers exactly the AoN blocks the program links.
 *
 * The note is allocated, so the linker places it in a PT_NOTE segment of the
 * loaded image and strip keeps it; its offsets are PC-relative, so they need
 * no relocation, even in a PIE. Everything is read from the new address
 * space, not from the file:
 *
 *   auxv AT_PHDR/AT_PHNUM -> program headers -> each PT_NOTE -> walk its notes
 *
 * Runs in the exec'ing task, in process context, before its first user
 * instruction (copy_from_user may fault pages in, so never in a probe
 * handler). No user code has run yet and an exec'd file cannot be written
 * (ETXTBSY), so the mapped bytes are exactly those of the file.
 */
#include <linux/auxvec.h>
#include <linux/elf.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/mm_types.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>

#include "aon.h"

/* The ELF loader refuses larger program header tables (load_elf_phdrs). */
#define AON_PHDRS_MAX 4096UL
/* PT_NOTE segments larger than this are skipped; ours is 24 bytes. */
#define AON_NOTE_SEG_MAX 4096UL

/* Value of auxv entry @type for @mm, or 0 if absent. */
static u64 auxv_get(struct mm_struct *mm, unsigned long type) {
  int i;

  for (i = 0; i + 1 < AT_VECTOR_SIZE && mm->saved_auxv[i] != AT_NULL; i += 2)
    if (mm->saved_auxv[i] == type)
      return mm->saved_auxv[i + 1];
  return 0;
}

/* Load bias (runtime - link-time address). load_elf_binary() sets
 * mm->start_code to the lowest p_vaddr of an executable PT_LOAD plus the load
 * bias, so subtracting that p_vaddr gives the bias for ET_EXEC (0), PIE and
 * static-pie alike -- the last one has no PT_PHDR to derive it from. */
static int load_bias(struct mm_struct *mm, const Elf64_Phdr *ph, size_t n,
                     u64 *bias) {
  u64 min_x = U64_MAX;
  size_t i;

  for (i = 0; i < n; i++)
    if (ph[i].p_type == PT_LOAD && (ph[i].p_flags & PF_X) &&
        ph[i].p_vaddr < min_x)
      min_x = ph[i].p_vaddr;
  if (min_x == U64_MAX)
    return -ENOEXEC;
  *bias = mm->start_code - min_x;
  return 0;
}

/* Walk the notes of one PT_NOTE segment: @size bytes copied into @seg from
 * runtime address @addr, entries padded to @align. Returns 0 and the region
 * on a match, -ENOENT otherwise. */
static int scan_notes(const u8 *seg, size_t size, u64 addr, size_t align,
                      u64 *start, u64 *end) {
  size_t off = 0;

  while (size - off >= sizeof(Elf64_Nhdr)) {
    const Elf64_Nhdr *n = (const Elf64_Nhdr *)(seg + off);
    size_t name_off = off + sizeof(*n);
    /* size_t arithmetic: a hostile n_namesz/n_descsz cannot wrap. */
    size_t desc_off = name_off + ALIGN((size_t)n->n_namesz, align);
    size_t next = desc_off + ALIGN((size_t)n->n_descsz, align);
    s32 d[2];

    if (next > size) /* truncated entry: stop */
      break;

    if (n->n_type == NT_AON_REGION &&
        n->n_namesz == sizeof(AON_NOTE_NAME) &&
        !memcmp(seg + name_off, AON_NOTE_NAME, sizeof(AON_NOTE_NAME)) &&
        n->n_descsz == sizeof(d)) {
      memcpy(d, seg + desc_off, sizeof(d));
      *start = addr + desc_off + (s64)d[0];
      *end = addr + desc_off + (s64)d[1];
      return 0;
    }
    off = next;
  }
  return -ENOENT;
}

int aon_elf_find_region(struct mm_struct *mm, u64 *start, u64 *end) {
  u64 phdr = auxv_get(mm, AT_PHDR), phnum = auxv_get(mm, AT_PHNUM), bias;
  Elf64_Phdr *ph;
  u8 *seg = NULL;
  size_t i;
  int ret;

  /* 1. Program headers, where the kernel mapped them (not an ELF: no auxv). */
  if (!phdr || !phnum || phnum > AON_PHDRS_MAX / sizeof(*ph) ||
      auxv_get(mm, AT_PHENT) != sizeof(*ph))
    return -ENOEXEC;

  ph = kmalloc_array(phnum, sizeof(*ph), GFP_KERNEL);
  if (!ph)
    return -ENOMEM;
  if (copy_from_user(ph, (const void __user *)phdr, phnum * sizeof(*ph))) {
    ret = -EFAULT;
    goto out;
  }

  ret = load_bias(mm, ph, phnum, &bias);
  if (ret)
    goto out;

  seg = kmalloc(AON_NOTE_SEG_MAX, GFP_KERNEL);
  if (!seg) {
    ret = -ENOMEM;
    goto out;
  }

  /* 2. Each PT_NOTE segment: copy it in and look for the AoN note. */
  ret = -ENOENT; /* no AoN note: an ordinary program */
  for (i = 0; i < phnum; i++) {
    u64 addr = bias + ph[i].p_vaddr;

    if (ph[i].p_type != PT_NOTE || ph[i].p_filesz > AON_NOTE_SEG_MAX)
      continue;
    if (copy_from_user(seg, (const void __user *)addr, ph[i].p_filesz)) {
      ret = -EFAULT;
      break;
    }
    ret = scan_notes(seg, ph[i].p_filesz, addr, ph[i].p_align == 8 ? 8 : 4,
                     start, end);
    if (ret != -ENOENT)
      break;
  }
  if (!ret && *start >= *end)
    ret = -EINVAL;

out:
  kfree(seg);
  kfree(ph);
  return ret;
}
