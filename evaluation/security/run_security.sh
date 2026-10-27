#!/bin/sh
# run_security.sh - run the correctness and security rows of the evaluation
# (C1-C5, S1-S4) and record results.
#
#   C1          cat on three files, baseline vs defended: same output + exit
#   C3 C4 C5    static evidence on cat_defended (and sig_defended): verifier,
#               note, aligned `syscall` / `0f 05` / `0f 0b` census, linked blocks
#   C2          sig correctness (signal while armed -> egress refused -> retry)
#   S1 S2       cat aligned / misaligned (vector A / B)
#   S3 S4       sig attack-unarmed / attack-armed (handler reuses read egress)
#   (all)       one `strace -n -k` trace per case (system call + issuing stack)
#
# Every dynamic case runs once as the REPRESENTATIVE run (stdout, stderr, exit
# status and the aon_mod kernel log lines it caused are kept verbatim), then
# REPEAT more times to show the outcome is deterministic (outcome counts and the
# module's signal_disarms counter, which unlike the log is not rate limited).
#
# Needs root for insmod/rmmod/dmesg: run as root, or set AON_SUDO to a command
# that runs its arguments as root (default: sudo).
#
#   evaluation/security/run_security.sh [outdir]   (default: evaluation/results/<date>)
set -eu

ev="$(cd "$(dirname "$0")" && pwd)"
top="$(cd "$ev/../.." && pwd)"
out="${1:-$top/evaluation/results/$(date +%Y%m%d-%H%M%S)}"
REPEAT="${REPEAT:-100}"
mkdir -p "$out/runs" "$out/static" "$out/inputs"
out="$(cd "$out" && pwd)"

root() { if [ "$(id -u)" = 0 ]; then "$@"; else ${AON_SUDO:-sudo} "$@"; fi; }
klog() { root dmesg | sed 's/^\[[ 0-9.]*\] //'; }
disarms() { cat /sys/module/aon_mod/parameters/signal_disarms; }

cat_dir="$top/user_aonlibc_cat"
sig_dir="$top/user_aonlibc_signal"

# ---- environment ---------------------------------------------------------
{
  echo "date:      $(date -Is)"
  echo "commit:    $(git -C "$top" rev-parse --short HEAD) ($(git -C "$top" rev-parse --abbrev-ref HEAD))$(git -C "$top" diff --quiet HEAD -- aonlibc kernel tools user_aonlibc_cat user_aonlibc_signal || echo ', DIRTY')"
  echo "kernel:    $(uname -srm)"
  echo "cpu:       $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | sed 's/^ //')"
  echo "virt:      $(systemd-detect-virt 2>/dev/null || echo unknown)"
  echo "gcc:       $(gcc --version | head -1)"
  echo "ld:        $(ld --version | head -1)"
  echo "aslr:      $(cat /proc/sys/kernel/randomize_va_space)"
  echo "repeat:    $REPEAT"
} > "$out/environment.txt"

# ---- build (clean) -------------------------------------------------------
make -C "$top" clean > /dev/null
make -C "$top" all > "$out/build.log" 2>&1

# ---- static evidence: C3, C4, C5 -----------------------------------------
for b in "$cat_dir/cat" "$cat_dir/cat_defended" "$sig_dir/sig" "$sig_dir/sig_defended"; do
  n="$(basename "$b")"
  lib="$(dirname "$b")/aon_syscalls.aon.o"
  python3 "$ev/analyze_binary.py" "$b" "$lib" > "$out/static/$n.json"
  case "$n" in *_defended)
    "$top/tools/verify_aon.sh" "$b" > "$out/static/$n.verify.txt" 2>&1 \
      && echo "exit 0" >> "$out/static/$n.verify.txt" \
      || echo "exit $?" >> "$out/static/$n.verify.txt"
    readelf -n "$b" > "$out/static/$n.note.txt"
    objdump -d -j aon_text "$b" > "$out/static/$n.aon_text.dis"
  esac
done
objdump -d --disassemble=benign_compute "$cat_dir/cat_defended" \
  > "$out/static/cat_defended.benign_compute.dis"

# ---- fresh module (counters at 0) ---------------------------------------
lsmod | grep -q '^aon_mod ' && root rmmod aon_mod
klog_start="$(klog | wc -l)"
root insmod "$top/kernel/aon_mod.ko"
echo "neutralize_mode=$(cat /sys/module/aon_mod/parameters/neutralize_mode)" \
  >> "$out/environment.txt"

# ---- inputs for C1 -------------------------------------------------------
"$cat_dir/reset.sh" "$out/inputs/victim.txt" > /dev/null
cp /etc/services "$out/inputs/services.txt"
head -c 1048576 /dev/urandom > "$out/inputs/random.bin"

# ---- one representative run ----------------------------------------------
# rep <id> <dir> <binary> <operand>
# Leaves runs/<id>.{stdout,stderr,exit,klog,disarms}. Runs from the scenario
# dir so the binaries see the same cwd as `make run`.
rep() {
  id="$1"; dir="$2"; bin="$3"; arg="$4"
  before="$(klog | wc -l)"; d0="$(disarms)"
  set +e
  (cd "$dir" && "./$bin" "$arg") > "$out/runs/$id.stdout" 2> "$out/runs/$id.stderr"
  echo $? > "$out/runs/$id.exit"
  set -e
  sleep 1
  klog | tail -n +"$((before + 1))" | grep '^aon:' > "$out/runs/$id.klog" || true
  echo $(( $(disarms) - d0 )) > "$out/runs/$id.disarms"
  echo "$dir/$bin $arg" > "$out/runs/$id.cmd"
  # pr_*_ratelimited allows 10 lines / 5 s per call site: leave the window
  # empty for the next representative run.
  sleep 5
}

# repeat <id> <dir> <binary> <operand>: REPEAT runs, count outcomes.
# Outcome = exit status + whether the attacker's /bin/echo line was printed.
repeat_runs() {
  id="$1"; dir="$2"; bin="$3"; arg="$4"
  d0="$(disarms)"
  : > "$out/runs/$id.outcomes"
  i=0
  while [ "$i" -lt "$REPEAT" ]; do
    set +e
    o="$(cd "$dir" && "./$bin" "$arg" 2>/dev/null)"; rc=$?
    set -e
    case "$o" in *"[attacker]"*) w=execve ;; *) w=no-execve ;; esac
    echo "exit=$rc $w" >> "$out/runs/$id.outcomes"
    i=$((i + 1))
  done
  sort "$out/runs/$id.outcomes" | uniq -c | sed 's/^ *//' > "$out/runs/$id.summary"
  echo $(( $(disarms) - d0 )) > "$out/runs/$id.repeat_disarms"
  rm "$out/runs/$id.outcomes"
}

CASES="
C1-victim-base   $cat_dir cat          $out/inputs/victim.txt
C1-victim-def    $cat_dir cat_defended $out/inputs/victim.txt
C1-services-base $cat_dir cat          $out/inputs/services.txt
C1-services-def  $cat_dir cat_defended $out/inputs/services.txt
C1-random-base   $cat_dir cat          $out/inputs/random.bin
C1-random-def    $cat_dir cat_defended $out/inputs/random.bin
S1-base          $cat_dir cat          aligned
S1-def           $cat_dir cat_defended aligned
S2-base          $cat_dir cat          misaligned
S2-def           $cat_dir cat_defended misaligned
C2-base          $sig_dir sig          correctness
C2-def           $sig_dir sig_defended correctness
S3-base          $sig_dir sig          attack-unarmed
S3-def           $sig_dir sig_defended attack-unarmed
S4-base          $sig_dir sig          attack-armed
S4-def           $sig_dir sig_defended attack-armed
"

echo "$CASES" | while read -r id dir bin arg; do
  [ -n "$id" ] || continue
  echo "rep    $id"; rep "$id" "$dir" "$bin" "$arg"
done
echo "$CASES" | while read -r id dir bin arg; do
  [ -n "$id" ] || continue
  case "$id" in C1-random*|C1-services*) continue ;; esac
  echo "repeat $id"; repeat_runs "$id" "$dir" "$bin" "$arg"
done

# ---- system call traces --------------------------------------------------
# strace -n -k: every system call with its number and the user stack that
# issued it (innermost frame = return address, i.e. the instruction after the
# `syscall`). Its syscall-entry stop comes before x64_sys_call, where aon_mod
# refuses, so a refused call shows its ORIGINAL number with -1 ENOSYS.
# C1 also gets a plain trace reduced to a per-system-call count.
echo "$CASES" | while read -r id dir bin arg; do
  [ -n "$id" ] || continue
  echo "strace $id"
  set +e
  case "$id" in
    C1-*)
      (cd "$dir" && strace -qq -o "$out/runs/$id.trace.tmp" "./$bin" "$arg") > /dev/null 2>&1
      echo $? > "$out/runs/$id.strace_exit"
      sed -n 's/^\([a-z_0-9]*\)(.*/\1/p' "$out/runs/$id.trace.tmp" | sort | uniq -c \
        | awk '{print $2, $1}' > "$out/runs/$id.calls"
      rm "$out/runs/$id.trace.tmp"
      ;;
  esac
  case "$id" in C1-services*|C1-random*) set -e; continue ;; esac
  (cd "$dir" && strace -n -k -o "$out/runs/$id.strace" "./$bin" "$arg") > /dev/null 2>&1
  echo $? > "$out/runs/$id.strace_exit"
  set -e
done

klog | tail -n +"$((klog_start + 1))" | grep '^aon:' > "$out/kernel_log_full.txt" || true
# The 1 MiB input and its two copies on stdout are kept only as
# "<sha256> <size>" (summarize.py reads them back).
for f in "$out/inputs/random.bin" "$out"/runs/C1-random-*.stdout; do
  echo "$(sha256sum "$f" | cut -d' ' -f1) $(stat -c %s "$f")" > "$f.sha256" && rm "$f"
done
python3 "$ev/summarize.py" "$out" > "$out/RESULTS.md"
echo "results: $out/RESULTS.md"
