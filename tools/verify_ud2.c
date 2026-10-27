/*
 * verify_ud2.c - build-time verifier for the coarse AoN region check.
 *
 * The kernel module trusts "any #UD inside the AoN region is an ingress gate".
 * That is only sound if the AoN region contains no 0f 0b (ud2) byte pair at
 * ANY offset -- aligned or misaligned -- other than the declared ingress
 * gates. This tool proves that invariant on the final linked ELF, so a stray
 * ud2 that slips in via some future constant or instruction encoding fails the
 * build.
 *
 * Usage:
 *   verify_ud2 <elf> <ingress_gate_vaddr>...
 *       scan every executable (PF_X) PT_LOAD segment in full.
 *   verify_ud2 --region <lo> <hi> <elf> <ingress_gate_vaddr>...
 *       scan only bytes whose virtual address lies in [lo, hi).
 *
 * All addresses are hex (0x... or bare hex). Exit status: 0 = clean, 1 = a
 * disallowed ud2 was found, 2 = usage/IO error.
 *
 * A "hit" is a 0x0f byte immediately followed by 0x0b; its address is the
 * address of the 0x0f (where a control transfer would land to execute ud2;
 * a misaligned one if it is not an intended instruction boundary).
 */
#define _GNU_SOURCE
#include <elf.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint64_t parse_hex(const char *s) {
  return (uint64_t)strtoull(s, NULL, 16);
}

int main(int argc, char **argv) {
  int argi = 1;
  int have_region = 0;
  uint64_t rlo = 0, rhi = ~0ULL;

  if (argc > 1 && strcmp(argv[1], "--region") == 0) {
    if (argc < 5) {
      fprintf(stderr, "usage: %s --region <lo> <hi> <elf> <gate>...\n", argv[0]);
      return 2;
    }
    rlo = parse_hex(argv[2]);
    rhi = parse_hex(argv[3]);
    have_region = 1;
    argi = 4;
  }

  if (argi >= argc) {
    fprintf(stderr, "usage: %s [--region <lo> <hi>] <elf> <gate>...\n", argv[0]);
    return 2;
  }

  const char *path = argv[argi++];

  /* Remaining args are the allowed ingress gate virtual addresses. */
  int ngates = argc - argi;
  uint64_t *gates = NULL;
  if (ngates > 0) {
    gates = calloc((size_t)ngates, sizeof(*gates));
    for (int i = 0; i < ngates; i++)
      gates[i] = parse_hex(argv[argi + i]);
  }

  FILE *f = fopen(path, "rb");
  if (!f) {
    perror("fopen");
    return 2;
  }
  fseek(f, 0, SEEK_END);
  long fsz = ftell(f);
  fseek(f, 0, SEEK_SET);
  if (fsz <= 0) {
    fprintf(stderr, "verify_ud2: %s: empty/unreadable\n", path);
    fclose(f);
    return 2;
  }
  unsigned char *buf = malloc((size_t)fsz);
  if (!buf || fread(buf, 1, (size_t)fsz, f) != (size_t)fsz) {
    fprintf(stderr, "verify_ud2: %s: read failed\n", path);
    fclose(f);
    return 2;
  }
  fclose(f);

  if ((size_t)fsz < sizeof(Elf64_Ehdr) ||
      memcmp(buf, ELFMAG, SELFMAG) != 0 || buf[EI_CLASS] != ELFCLASS64) {
    fprintf(stderr, "verify_ud2: %s: not an ELF64 file\n", path);
    return 2;
  }

  Elf64_Ehdr *eh = (Elf64_Ehdr *)buf;
  Elf64_Phdr *ph = (Elf64_Phdr *)(buf + eh->e_phoff);

  int hits = 0, gate_hits = 0, stray = 0, scanned_segs = 0;

  for (unsigned i = 0; i < eh->e_phnum; i++) {
    if (ph[i].p_type != PT_LOAD || !(ph[i].p_flags & PF_X))
      continue;
    scanned_segs++;

    uint64_t seg_off = ph[i].p_offset;
    uint64_t seg_va = ph[i].p_vaddr;
    uint64_t seg_fsz = ph[i].p_filesz;
    if (seg_off + seg_fsz > (uint64_t)fsz)
      seg_fsz = (uint64_t)fsz - seg_off; /* be defensive */

    for (uint64_t j = 0; j + 1 < seg_fsz; j++) {
      uint64_t va = seg_va + j; /* vaddr of a candidate 0x0f */
      if (have_region && (va < rlo || va >= rhi))
        continue;
      if (buf[seg_off + j] == 0x0f && buf[seg_off + j + 1] == 0x0b) {
        int allowed = 0;
        for (int g = 0; g < ngates; g++)
          if (gates[g] == va) {
            allowed = 1;
            break;
          }
        hits++;
        if (allowed) {
          gate_hits++;
          printf("  ok   ud2 @ 0x%016" PRIx64 "  (declared ingress gate)\n", va);
        } else {
          stray++;
          printf("  BAD  ud2 @ 0x%016" PRIx64 "  (undeclared -- not an ingress gate!)\n", va);
        }
      }
    }
  }

  printf("verify_ud2: %s: scanned %d exec segment(s)%s; %d ud2 (%d gate, %d stray)\n",
         path, scanned_segs, have_region ? " within the AoN region" : "", hits, gate_hits, stray);

  free(buf);
  free(gates);

  if (stray) {
    fprintf(stderr, "verify_ud2: FAIL - %d undeclared ud2 in the AoN "
                    "region; the coarse region check is UNSOUND.\n",
            stray);
    return 1;
  }
  if (ngates > 0 && gate_hits < ngates)
    fprintf(stderr, "verify_ud2: WARN - only %d of %d declared ingress gates "
                    "found as ud2 (check their addresses).\n",
            gate_hits, ngates);
  printf("verify_ud2: OK\n");
  return 0;
}
