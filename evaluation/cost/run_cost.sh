#!/bin/sh
# run_cost.sh - run the cost block of the evaluation (rows P0-P3) and record
# raw results, then runs analyze_cost.py (COST.md and two CSVs).
#
#   P0   module NOT loaded: TSC calibration (tsc_calib.c), then the reference
#        costs, every operation timed with the TSC (syscall_latency <op>)
#   P1   cost per protected call: bench vs bench_defended
#   P2   same loop under seccomp: bench_seccomp (nr), bench_seccomp_ip (nr+ip)
#        P1/P2: every call timed in-program with the TSC (`bench stream`),
#        once per write size in SIZES: 0 is write(-1, buf, 0), SIZE > 0 real
#        writes of SIZE bytes to the file SINK, kept within MAX_FILE_SIZE
#   P3   an UNPROTECTED process (bench stream) while the module is
#          unloaded / loaded and idle
#
# A run is one pass of everything: P0 once, then every configuration once,
# back to back, as a fresh process each. The length of a configuration (P0
# operations included) is not chosen here: batch_means.py reads its stream
# until the batch means are about uncorrelated and the CI half-width is below
# GAMMA of the estimate. RUNS runs are made per invocation; an existing
# results directory is appended to (its runs are numbered on), so one can
# start with RUNS=1 and add runs later. The measured process is pinned to CPU
# $CPU.
#
#   evaluation/cost/run_cost.sh [config]   (default: evaluation/cost/cost.conf)
#
# Settings come from the config file; one also set in the environment wins
# (RUNS=4 evaluation/cost/run_cost.sh). The script needs root (insmod): not
# root, it runs itself again under sudo. OWNER (default: who ran it) gets the
# results at the end.
set -eu

self="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
conf="$(cd "$(dirname "${1:-$self}")" && pwd)/$(basename "${1:-cost.conf}")"
top="$(cd "$(dirname "$self")/../.." && pwd)"
cd "$top"
git() { command git -c safe.directory="$top" "$@"; }  # we run as root

# ---- settings: environment, then the config file, then the defaults ---------
KEYS="OUT RUNS GAMMA MAXN MAXN_DEFENDED CPU OWNER QUIET SIZES SINK MAX_FILE_SIZE WARMUP N0 K_TEST K_FINAL RHO ALPHA"
for k in $KEYS; do eval "_env_$k=\${$k-}"; done
. "$conf"
for k in $KEYS; do eval "[ -z \"\$_env_$k\" ] || $k=\$_env_$k"; done
: "${OUT:=evaluation/results/cost-$(git rev-parse --abbrev-ref HEAD | tr / -)-$(git rev-parse --short HEAD)}"
: "${RUNS:=1}" "${GAMMA:=0.01}" "${MAXN:=33554432}" "${MAXN_DEFENDED:=8388608}" "${CPU:=2}"
: "${QUIET:=1}" "${SIZES:=0}" "${SINK:=/dev/shm/aon_bench}" "${MAX_FILE_SIZE:=1048576}"
# batch_means.py inputs: only those set are passed, the others keep its defaults
bmopts=""
for kv in WARMUP:--warmup N0:--n K_TEST:--k-test K_FINAL:--k-final RHO:--rho ALPHA:--alpha; do
  eval "v=\${${kv%%:*}-}"
  [ -z "$v" ] || bmopts="$bmopts ${kv#*:} $v"
done
: "${OWNER:=${SUDO_UID:-$(id -u)}:${SUDO_GID:-$(id -g)}}"

if [ "$(id -u)" != 0 ]; then
  set -- "$self" "$conf"
  for k in $KEYS; do eval "set -- \"$k=\${$k-}\" \"\$@\""; done
  exec sudo env "$@"
fi

out="$OUT"
case "$out" in /*) ;; *) out="$top/$out" ;; esac
mkdir -p "$out/p0" "$out/lat" "$out/collateral"
out="$(cd "$out" && pwd)"

bd="$top/evaluation/bench"
mod="$top/kernel/aon_mod.ko"
loaded() { lsmod | grep -q '^aon_mod '; }
load() { loaded || insmod "$mod"; }
unload() { if loaded; then rmmod aon_mod; fi; }
quiet() { sleep "$QUIET"; }

# Runs already in $out: number on after the last one.
last=$(ls "$out/p0" | sed -n 's/^tsc\.r\([0-9]*\)\.txt$/\1/p' | sort -n | tail -1)
first=$(( ${last:-0} + 1 ))
end=$(( first + RUNS - 1 ))

# ---- environment (one section per invocation) -----------------------------
{
  echo "== runs $first-$end"
  echo "date:        $(date -Is)"
  echo "commit:      $(git rev-parse --short HEAD) ($(git rev-parse --abbrev-ref HEAD))$([ -z "$(git status --porcelain -- aonlibc kernel tools evaluation/bench evaluation/cost)" ] || echo ', uncommitted changes in the measured sources')"
  echo "kernel:      $(uname -srm)"
  echo "cmdline:     $(cat /proc/cmdline)"
  echo "cpu:         $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | sed 's/^ //')"
  echo "vcpus:       $(nproc)"
  echo "virt:        $(systemd-detect-virt 2>/dev/null || echo unknown)"
  echo "gcc:         $(gcc --version | head -1)"
  echo "bpf_jit:     $(cat /proc/sys/net/core/bpf_jit_enable)"
  echo "aslr:        $(cat /proc/sys/kernel/randomize_va_space)"
  echo "cpu pinned:  $CPU"
  echo "gamma:       $GAMMA (target relative CI half-width)"
  echo "max calls:   $MAXN (bench_defended: $MAXN_DEFENDED)"
  echo "batch means: ${bmopts# }${bmopts:+ }(others: batch_means.py defaults; each .json has all)"
  echo "pause:       $QUIET s before each configuration"
  echo "write sizes: $SIZES"
  echo "sink:        $SINK ($(stat -f -c %T "$(dirname "$SINK")"), rewound at $MAX_FILE_SIZE bytes)"
  echo "mitigations:"
  grep . /sys/devices/system/cpu/vulnerabilities/* | sed 's|.*/||; s/^/  /'
  echo
} >> "$out/environment.txt"

# ---- build ---------------------------------------------------------------
p0bin="$out/syscall_latency"
tscbin="$out/tsc_calib"
{
  make -C "$bd" clean all &&
  make -C "$top/kernel" &&
  gcc -O2 -Wall -o "$p0bin" "$top/evaluation/cost/syscall_latency.c" &&
  gcc -O2 -Wall -o "$tscbin" "$top/evaluation/cost/tsc_calib.c"
} > "$out/build.log" 2>&1 || {   # set -e is off in here: chained with &&
  tail -20 "$out/build.log" >&2
  echo "build failed, see $out/build.log" >&2
  exit 1
}
for b in bench bench_defended bench_seccomp bench_seccomp_ip; do
  objdump -d --no-show-raw-insn "$bd/$b" | awk '/<main>:/,/^$/' > "$out/build.$b.main.dis"
done
objdump -d "$bd/bench_defended" -j aon_text > "$out/build.bench_defended.aon_text.dis"

# bm <outfile prefix> <max calls> <command...>: batch means on the stream of
# <command>, writes <prefix>.bin (retained samples), .json (estimate), .log
bm() {
  prefix=$1 max=$2
  shift 2
  quiet
  python3 "$top/evaluation/cost/batch_means.py" $bmopts --gamma "$GAMMA" --max "$max" --out "$prefix" \
    -- taskset -c "$CPU" "$@" > "$prefix.log"
}

for r in $(seq "$first" "$end"); do
  echo "run $r ($first-$end): $(date '+%H:%M:%S')"
  # ---- P0: calibration and reference costs, module not loaded ------------
  unload
  taskset -c "$CPU" "$tscbin" > "$out/p0/tsc.r$r.txt"
  for op in timer null badfd enosys int3; do
    bm "$out/p0/$op.r$r" "$MAXN" "$p0bin" "$op"
  done
  bm "$out/p0/ud2.r$r" "$MAXN_DEFENDED" "$p0bin" ud2

  # ---- P1/P2: per-call latency, module loaded ----------------------------
  # Size 0 keeps the names lat/<build>.r<k>; SIZE > 0 is lat/<build>.s<SIZE>.r<k>
  load
  bm "$out/lat/nop.r$r" "$MAXN" "$bd/bench" stream-nop
  for s in $SIZES; do
    if [ "$s" = 0 ]; then sfx= sargs=; else sfx=".s$s" sargs="$s $SINK $MAX_FILE_SIZE"; fi
    for b in bench bench_defended bench_seccomp bench_seccomp_ip; do
      if [ "$b" = bench_defended ]; then max=$MAXN_DEFENDED; else max=$MAXN; fi
      bm "$out/lat/$b$sfx.r$r" "$max" "$bd/$b" stream $sargs
    done
  done
  rm -f "$SINK"

  # ---- P3: an unprotected process, module states -------------------------
  unload; bm "$out/collateral/unloaded.r$r"    "$MAXN" "$bd/bench" stream
  load;   bm "$out/collateral/loaded_idle.r$r" "$MAXN" "$bd/bench" stream
done
rm "$p0bin" "$tscbin"
load   # leave the module loaded, as it was found by run_security.sh

dmesg | sed 's/^\[[ 0-9.]*\] //' | grep '^aon:' | tail -50 > "$out/kernel_log_tail.txt" || true
PYTHONDONTWRITEBYTECODE=1 python3 "$top/evaluation/cost/analyze_cost.py" "$out" || echo "analyze_cost.py failed"
chown -R "$OWNER" "$out"
echo "runs $first-$end: $out/COST.md"
