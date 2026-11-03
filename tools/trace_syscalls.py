#!/usr/bin/env python3
"""Log every system call of a program, run under gdb.

Usage:  trace_syscalls.py [-o LOG] BINARY [ARG...]      (LOG: syscalls.log)
Exit:   the program's exit status (128 + signal if a signal killed it).

For each system call the log shows its name, its site (the `syscall`
instruction, its symbol and the mapping it is part of), its arguments, its
return value, and the mappings it added (+) or removed (-). Signals are
logged with the address they hit, except SIGTRAP, which gdb keeps for
itself (so a program that single-steps itself does not work under it). The
program's own output stays on the terminal.

The same file is both the command and the gdb script: run with python3 it
starts `gdb -x <this file> --args BINARY ARG...`; loaded by gdb it traces.

gdb stops twice per system call, at entry and at return, so the stops
alternate (assumes a single thread). Everything but the return value is read
at entry, since a successful execve returns into the new program. The log
ends at the entry of exit/exit_group, which never return.
"""

import os
import signal

try:
    import gdb
except ImportError:                         # run as a command: start gdb
    import argparse
    p = argparse.ArgumentParser(usage="%(prog)s [-o LOG] BINARY [ARG...]")
    p.add_argument("-o", dest="log", default="syscalls.log")
    p.add_argument("binary")
    p.add_argument("args", nargs=argparse.REMAINDER)
    a = p.parse_args()
    os.environ["SYSCALL_LOG"] = os.path.abspath(a.log)
    os.execvp("gdb", ["gdb", "-q", "-batch", "-x", os.path.abspath(__file__),
                      "--args", a.binary, *a.args])

import xml.etree.ElementTree as ET

NAMES = {int(s.get("number")): s.get("name") for s in
         ET.parse("/usr/share/gdb/syscalls/amd64-linux.xml").iter("syscall")}
# Path arguments to print as strings: system call nr -> argument index.
PATHS = {2: 0, 4: 0, 21: 0, 59: 0, 89: 0, 257: 1}  # open stat access execve readlink openat
ARGS = ("rdi", "rsi", "rdx", "r10", "r8", "r9")

log = open(os.environ.get("SYSCALL_LOG", "syscalls.log"), "w")


def reg(name):
    return int(gdb.parse_and_eval("$" + name)) & (2**64 - 1)


def mappings():
    """The lines of /proc/<pid>/maps, as (start, end, perms, offset, path)."""
    result = []
    with open("/proc/%d/maps" % gdb.selected_inferior().pid) as f:
        for line in f:
            fields = line.split(None, 5)
            start, end = (int(x, 16) for x in fields[0].split("-"))
            path = fields[5].strip() if len(fields) > 5 else "[anon]"
            result.append((start, end, fields[1], int(fields[2], 16), path))
    return result


def show(m):
    start, end, perms, offset, path = m
    return "%#014x-%#014x %6dK  %s  off %-8s  %s" % (
        start, end, (end - start) // 1024, perms, "%#x" % offset, path)


def where(addr):
    """Its symbol (with section and file) and the mapping it is part of."""
    symbol = gdb.execute("info symbol %#x" % addr, to_string=True).strip()
    part_of = next(("%s %s" % (p, path) for s, e, p, _, path in mappings()
                    if s <= addr < e), "unmapped")
    return symbol, part_of


def on_entry(n):
    nr = reg("orig_rax")
    site = reg("pc") - 2                    # `syscall` is 2 bytes long
    args = [reg(r) for r in ARGS]
    symbol, part_of = where(site)
    log.write("#%-3d %s (nr %d)\n" % (n, NAMES.get(nr, "?"), nr))
    log.write("    site    %#x  %s\n" % (site, symbol))
    log.write("    part of %s\n" % part_of)
    log.write("    args    %s\n" % ", ".join("%#x" % a for a in args))
    if nr in PATHS:
        path = gdb.parse_and_eval("(char *)%#x" % args[PATHS[nr]]).string()
        log.write('    path    "%s"\n' % path)
    return nr


def on_return(before):
    ret = reg("rax")
    if ret >= 2**64 - 4095:                 # -1 .. -4095: an error
        ret -= 2**64
        log.write("    ret     %d (%s)\n" % (ret, os.strerror(-ret)))
    else:
        log.write("    ret     %#x (%d)\n" % (ret, ret))
    after = mappings()
    gone = [m for m in before if m not in after]
    added = [m for m in after if m not in before]
    if gone or added:
        log.write("    address space:\n")
        log.writelines("      - %s\n" % show(m) for m in gone)
        log.writelines("      + %s\n" % show(m) for m in added)
    log.write("\n")
    return after


def on_signal():
    name = signal.Signals(int(gdb.parse_and_eval("$_siginfo.si_signo"))).name
    pc = reg("pc")
    symbol, part_of = where(pc)
    log.write("signal %s\n    at      %#x  %s\n    part of %s\n\n"
              % (name, pc, symbol, part_of))


def exit_status():
    """How the program ended, and the matching shell exit status."""
    sig = gdb.parse_and_eval("$_exitsignal")
    if sig.type.code != gdb.TYPE_CODE_VOID:
        return "killed by %s" % signal.Signals(int(sig)).name, 128 + int(sig)
    code = int(gdb.parse_and_eval("$_exitcode"))
    return "exited with code %d" % code, code


# Keep gdb quiet: the terminal shows only the program's own output.
gdb.execute("set pagination off")
gdb.execute("set print inferior-events off")
gdb.execute("handle all nostop noprint pass", to_string=True)
gdb.execute("catch syscall", to_string=True)
syscall_catch = gdb.breakpoints()[-1]
gdb.execute("catch signal", to_string=True)  # every signal but SIGTRAP/SIGINT
for b in gdb.breakpoints():
    b.silent = True

stop = [None]
gdb.events.stop.connect(lambda event: stop.__setitem__(0, event))
gdb.execute("run", to_string=True)

maps = []
if gdb.selected_inferior().pid:
    maps = mappings()
    log.write("address space at the first stop:\n")
    log.writelines("    %s\n" % show(m) for m in maps)
    log.write("\n")

n = 0
at_entry = True
while gdb.selected_inferior().pid:
    if syscall_catch not in getattr(stop[0], "breakpoints", ()):
        on_signal()
    elif at_entry:
        n += 1
        if on_entry(n) in (60, 231):                 # exit, exit_group: never return
            code = reg("rdi") & 0xff
            log.write("\nexited with code %d\n" % code)
            gdb.execute("kill", to_string=True)
            break
        at_entry = False
    else:
        maps = on_return(maps)
        at_entry = True
    log.flush()
    gdb.execute("continue", to_string=True)
else:
    how, code = exit_status()
    log.write("%s\n" % how)
log.close()
print("trace: %d system calls logged to %s" % (n, log.name))
gdb.execute("quit %d" % code)               # exit with the program's status
