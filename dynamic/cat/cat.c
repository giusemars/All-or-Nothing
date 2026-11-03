/*
 * cat.c - glibc `cat` victim + attack driver for the All-or-Nothing PoC.
 *
 * ACADEMIC BASELINE (undefended control case). Unlike user/cat (nolibc, static,
 * hardened library), this is an ordinary dynamically linked glibc `cat` with no
 * AoN mechanism: open -> read loop -> write stdout -> close, all through
 * libc.so.6. Two reserved operands select an attack instead:
 *   <filename>  cat the file for real;
 *   aligned     reuse the `syscall` inside glibc's read() wrapper  -> vector A;
 *   misaligned  reuse the misaligned site in benign_compute        -> vector B.
 *
 * Both reach an `execve` (nr 59) the victim never invokes, replacing the image
 * with /bin/echo (visible, harmless). With no defense here, both vectors win.
 *
 * Usage: ./cat <filename|aligned|misaligned>
 */
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "cat.h"

/* execve payload: /bin/echo prints this and exits -- no network, no privilege,
 * just proof control reached an unintended execve. */
static char *const EVIL_ARGV[] = {
    "/bin/echo",
    "[attacker] execve() hijack succeeded -- process image replaced",
    0,
};
static char *const EVIL_ENVP[] = {0};

/* Vector A's aligned gadget: the `syscall` inside glibc's read() wrapper. The
 * attacker's address leak is simulated by scanning read() for the 0f 05 opcode
 * (read() is `... ; syscall ; cmp ; jae ; ret`, so the first match is it). */
static void *leak_read_syscall(void) {
  const unsigned char *p = (const unsigned char *)&read;

  for (int i = 0; i < 64; i++) {
    if (p[i] == 0x0f && p[i + 1] == 0x05)
      return (void *)(p + i);
  }
  return 0;
}

/* Genuine cat: stream `path` to stdout through glibc. Returns 0 on success. */
static int do_cat(const char *path) {
  char buf[256];

  int fd = open(path, O_RDONLY);
  if (fd < 0) {
    fprintf(stderr, "cat: open failed\n");
    return 1;
  }

  for (;;) {
    ssize_t n = read(fd, buf, sizeof(buf));
    if (n < 0) {
      fprintf(stderr, "cat: read failed\n");
      close(fd);
      return 2;
    }
    if (n == 0)
      break; /* EOF */
    write(1, buf, (size_t)n);
  }

  close(fd);
  return 0;
}

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "usage: cat <filename|aligned|misaligned>\n");
    return 1;
  }

  const char *arg = argv[1];

  if (strcmp(arg, "aligned") == 0) {
    /* Vector A: jump onto glibc read()'s `syscall` with %rax=59 (execve). */
    void *gadget = leak_read_syscall();
    if (!gadget) {
      fprintf(stderr, "cat: could not locate read syscall\n");
      return 4;
    }
    hijack(gadget, 59, (long)EVIL_ARGV[0], (long)EVIL_ARGV, (long)EVIL_ENVP);
    /* Reached only if execve did not run (here it normally does). */
    fprintf(stderr, "cat: aligned hijack did not run execve\n");
    return 3;
  }

  if (strcmp(arg, "misaligned") == 0) {
    /* Vector B: jump two bytes into benign_compute's immediate -> `syscall`. */
    hijack((void *)((char *)benign_compute + 2), 59, (long)EVIL_ARGV[0],
           (long)EVIL_ARGV, (long)EVIL_ENVP);
    fprintf(stderr, "cat: misaligned hijack did not run execve\n");
    return 3;
  }

  return do_cat(arg); /* not a reserved operand: cat it for real */
}
