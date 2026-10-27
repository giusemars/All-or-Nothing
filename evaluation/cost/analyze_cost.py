#!/usr/bin/env python3
"""analyze_cost.py - turn the raw output of run_cost.sh into COST.md and two
CSVs.

  analyze_cost.py <results dir>

Every configuration of every run (one process) was measured by batch_means.py,
which left <config>.r<k>.json: the mean, its CI, the observations n it took,
whether it converged, and the inputs it ran with. COST.md presents them as
gathered, one row per configuration and run, converted to ns with the run's
TSC calibration (p0/tsc.r<k>.txt, tsc_calib.c). A CI is the precision of that
one process's mean, not the process-to-process variability.

P1/P2 with real writes (run_cost.sh SIZES > 0) left lat/<build>.s<SIZE>.r<k>:
one more P1/P2 table and set of differences per SIZE found.

Differences between two configurations are computed per run (they ran back to
back in the same run); their CI combines the two CIs, the two processes being
independent. With 2 or more runs, COST.md also compares runs: the median of
the run means [min-max], and the between-run SD of the means against their
within-run SE (clearly above 1: processes differ by more than a run resolves,
more runs rather than longer ones narrow the result).

Also written: per_run.csv (one line per configuration and run, with
percentiles of the samples when the raw .bin is present: it is not committed)
and cost_numbers.csv (every number of COST.md).
"""
import csv
import glob
import json
import math
import os
import re
import sys

import numpy as np

import batch_means  # its defaults, for results older than the inputs in .json

out = sys.argv[1]
DOMINATES = 2.0  # between-run SD / within-run SE above which runs dominate

BLOCKS = [  # (directory, block, title, [(config, name, description)])
    ("p0", "P0", "reference costs (module not loaded)", [
        ("timer", "TSC read pair", "the timer alone; included in every sample"),
        ("null", "null system call", "`getpid` with a raw `syscall`"),
        ("badfd", "write(-1, buf, 0)", "raw `syscall`: what the benchmark loops on"),
        ("enosys", "invalid system call nr", "entry/exit only; = a refused call"),
        ("int3", "int3 + SIGTRAP", "#BP -> SIGTRAP handler -> `rt_sigreturn`"),
        ("ud2", "ud2 + SIGILL", "#UD -> SIGILL handler -> `rt_sigreturn`"),
    ]),
    ("lat", "P1/P2", "cost per protected call (module loaded)", [
        ("nop", "timer only", "`bench stream-nop`: the TSC read pair, no call"),
        ("bench", "baseline", "plain wrappers, not policed"),
        ("bench_seccomp", "seccomp (nr)", "filter on the system call number"),
        ("bench_seccomp_ip", "seccomp (nr + ip)", "number + instruction pointer"),
        ("bench_defended", "AoN (defended)", "AoN blocks: `ud2` ingress gate, checked `syscall`"),
    ]),
    ("collateral", "P3", "cost to unprotected processes (baseline `bench stream`)", [
        ("unloaded", "module not loaded", ""),
        ("loaded_idle", "loaded, no protected process", ""),
    ]),
]
DIFFS = [  # (block, a, b, label)
    ("P0", ("p0", "ud2"), ("p0", "int3"), "ud2 − int3: what is specific to #UD"),
    ("P1/P2", ("lat", "bench_seccomp"), ("lat", "bench"), "seccomp (nr) − baseline"),
    ("P1/P2", ("lat", "bench_seccomp_ip"), ("lat", "bench"), "seccomp (nr + ip) − baseline"),
    ("P1/P2", ("lat", "bench_defended"), ("lat", "bench"), "AoN (defended) − baseline"),
    ("P3", ("collateral", "loaded_idle"), ("collateral", "unloaded"),
     "loaded idle − not loaded"),
]

# P1/P2 with real writes: one block and its differences per SIZE found in lat/
BUILDS = [  # (build, name, description)
    ("bench", "baseline", "plain wrappers, not policed"),
    ("bench_seccomp", "seccomp (nr)", "filter on the system call number"),
    ("bench_seccomp_ip", "seccomp (nr + ip)", "number + instruction pointer"),
    ("bench_defended", "AoN (defended)", "AoN blocks: `ud2` ingress gate, checked `syscall`"),
]
SIZES = sorted({int(m.group(1)) for m in (
    re.match(r"bench\w*\.s(\d+)\.r\d+\.json$", os.path.basename(q))
    for q in glob.glob(os.path.join(out, "lat", "*.json"))) if m})
RATIOS = [("P1/P2", "")]  # (block, size suffix) of each AoN / baseline ratio
for size in SIZES:
    sfx, block = ".s%d" % size, "P1/P2 %d B" % size
    BLOCKS.insert(-1, ("lat", block, "real writes of %d bytes (module loaded)" % size,
                       [(b + sfx, name, d) for b, name, d in BUILDS]))
    DIFFS[-1:-1] = [(block, ("lat", b + sfx), ("lat", "bench" + sfx), name + " − baseline")
                    for b, name, _ in BUILDS[1:]]
    RATIOS.append((block, sfx))

BM_INPUTS = {  # batch_means.py inputs recorded in each .json, with its defaults
    "warmup": batch_means.WARMUP, "n0": batch_means.N0, "k_test": batch_means.K_TEST,
    "k_final": batch_means.K_FINAL, "rho_star": batch_means.RHO_STAR,
    "alpha": batch_means.ALPHA, "gamma": batch_means.GAMMA,
}


def runs_of(pattern):
    """{run: path} for a glob with one `r<k>` component."""
    res = {}
    for p in glob.glob(os.path.join(out, pattern)):
        m = re.search(r"(?:^|\.)r(\d+)\.", os.path.basename(p))
        res[int(m.group(1))] = p
    return res


def f(x, d=1, sign=False):
    return ("{:%s,.%df}" % ("+" if sign else "", d)).format(x)


def ci(h):
    """A CI half-width: 2 decimals below 1 ns, so it never shows as 0.0."""
    return "± < 0.01" if h < 0.005 else "± " + f(h, 2 if h < 1 else 1)


# ---- data ---------------------------------------------------------------------
tsc = {r: float(open(p).read()) for r, p in runs_of(os.path.join("p0", "tsc.r*.txt")).items()}
RUNS = sorted(tsc)
R = len(RUNS)

env = open(os.path.join(out, "environment.txt")).read()


def cap_from_env(r, ident):
    """n_max of a run older than n_max in .json: the caps run_cost.sh logged
    for the invocation that made run r (the lower one for the ~20 us ops)."""
    for a, b, rest in re.findall(r"^== runs (\d+)-(\d+)\n(.*?)(?=^== runs |\Z)", env, re.M | re.S):
        m = re.search(r"^max calls:\s+(\d+) \(bench_defended: (\d+)\)", rest, re.M)
        if m and int(a) <= r <= int(b):
            return int(m.group(2) if ident.split(".")[0] in ("bench_defended", "ud2")
                       else m.group(1))
    return None


run = {}  # (dir, config) -> {r: dict}, ns
for sub, _, _, configs in BLOCKS:
    for ident, _, _ in configs:
        d = run[(sub, ident)] = {}
        for r, path in runs_of(os.path.join(sub, ident + ".r*.json")).items():
            bm, t = json.load(open(path)), tsc[r]
            d[r] = dict(n=bm["n"], b=bm["batch_size"], mean=bm["estimate"] / t,
                        half=bm["half_width"] / t, se=bm["se"] / t, r1=bm["r1"],
                        conv=bm["converged"], indep=bm["independent"], precise=bm["precise"],
                        inputs={k: bm.get(k, v) for k, v in BM_INPUTS.items()},
                        n_max=bm.get("n_max") or cap_from_env(r, ident),
                        path=path[:-5])


def values(key):
    """The values of a batch_means.py input over every configuration and run."""
    return sorted({v["inputs"][key] for d in run.values() for v in d.values()})


def used(key, fmt="%g"):
    return ", ".join(fmt % x for x in values(key))


CL = ", ".join("%g%%" % (100 * (1 - a)) for a in values("alpha"))  # confidence level


def status(v):
    if v["conv"]:
        return "yes"
    return "**no** (%s)" % ", ".join(
        w for w, ok in (("correlated", v["indep"]), ("imprecise", v["precise"])) if not ok)


def diff(ka, kb):
    """{r: (a - b, CI half-width)} over the runs that have both."""
    da, db = run[ka], run[kb]
    return {r: (da[r]["mean"] - db[r]["mean"], math.hypot(da[r]["half"], db[r]["half"]),
                math.hypot(da[r]["se"], db[r]["se"]))
            for r in sorted(set(da) & set(db))}


def across(per_run):
    """per_run: {r: (mean, half, se)} -> median, min, max, SD between / SE within."""
    m = np.array([x[0] for x in per_run.values()])
    se = np.array([x[2] for x in per_run.values()])
    se_w = float(np.sqrt(np.mean(se ** 2)))
    sd_b = float(m.std(ddof=1)) if len(m) > 1 else float("nan")
    return float(np.median(m)), float(m.min()), float(m.max()), sd_b, se_w


# ---- per_run.csv ---------------------------------------------------------------
with open(os.path.join(out, "per_run.csv"), "w", newline="") as fh:
    w = csv.writer(fh)
    w.writerow(["file", "n", "n_max", "batch_size", "mean_ns", "ci_half_ns", "ci_half_rel", "r1",
                "converged", "median_ns", "p1_ns", "p10_ns", "p90_ns", "p99_ns", "p99.9_ns",
                "max_ns"])
    for d in run.values():
        for r, v in sorted(d.items()):
            row = [os.path.relpath(v["path"], out), v["n"], v["n_max"] or "", v["b"], "%.2f" % v["mean"],
                   "%.2f" % v["half"], "%.4f" % (v["half"] / v["mean"]), "%.3f" % v["r1"],
                   int(v["conv"])]
            if os.path.exists(v["path"] + ".bin"):  # raw samples: local only
                x = np.fromfile(v["path"] + ".bin", dtype=np.uint32) / tsc[r]
                row += ["%.1f" % q for q in np.percentile(x, [50, 1, 10, 90, 99, 99.9])]
                row += ["%.1f" % x.max()]
            w.writerow(row)

# ---- COST.md and cost_numbers.csv ------------------------------------------------
nums = []  # block, id, run, quantity, value, ci_lo, ci_hi, unit
commits = sorted(set(re.findall(r"^commit:\s+(.*)$", env, re.M)))
unconverged = [(k, r) for k, d in run.items() for r, v in d.items() if not v["conv"]]
P = []
p = P.append

p("# Cost evaluation (P0–P3)\n")
p("Generated by `evaluation/cost/analyze_cost.py` from the data in this directory "
  "(`run_cost.sh`); every number is also in `cost_numbers.csv`, every run in "
  "`per_run.csv`, the machine and settings in `environment.txt`.\n")
p("**%d run%s** (%s); commit %s.\n" % (R, "" if R == 1 else "s",
                                     ", ".join("r%d" % r for r in RUNS), "; ".join(commits)))
if len(commits) > 1:
    p("⚠ The runs come from different builds.\n")
if unconverged:
    p("⚠ Not converged (stopped at the call cap): %s.\n" % ", ".join(
        "%s r%d" % (k[1], r) for k, r in unconverged))

p("Each row is one configuration in one run (one process), measured by batch "
  "means (`batch_means.py`): the **mean** time per operation, its **%s CI** "
  "(± half-width, and relative to the mean), the **observations n** it took "
  "out of its cap **n_max** (n only doubles, so a run stops at the cap once "
  "the next doubling would exceed it), "
  "the lag-1 autocorrelation **ρ̂1** of its test batch means, and whether it "
  "**converged**: ρ̂1 < ρ* and CI < γ of the mean before the call cap "
  "(otherwise: correlated, imprecise). Every sample includes the timer (≈ the "
  "first row of P0), which cancels in a difference.\n" % CL)
m = re.search(r"^sink:\s+(.*)$", env, re.M)
if SIZES and m:
    p("Real writes (the P1/P2 <SIZE> B blocks) go to %s.\n" % m.group(1))
p("Batch means: d = %s discarded, first n = %s, %s test batches, ρ* = %s, %s "
  "batches for the CI, γ = %s, α = %s. TSC: %s ticks/ns.\n"
  % (used("warmup"), used("n0", "%d"), used("k_test"), used("rho_star"), used("k_final"),
     used("gamma"), used("alpha"), ", ".join("%.4f" % tsc[r] for r in RUNS)))
for r in RUNS:
    nums.append(("P0", "tsc", r, "TSC calibration", tsc[r], "", "", "ticks/ns"))

HEAD = ("| Configuration | run | mean, ns | %s CI, ns | rel. | n / n_max | ρ̂1 | converged |\n"
        "|---|---:|---:|---:|---:|---:|---:|---|" % CL)
for sub, block, title, configs in BLOCKS:
    p("## %s — %s\n" % (block, title))
    p(HEAD)
    for ident, name, _ in configs:
        for r, v in sorted(run[(sub, ident)].items()):
            p("| %s | %d | %s | %s | %.2f%% | %s | %.2f | %s |" % (
                name, r, f(v["mean"]), ci(v["half"]), 100 * v["half"] / v["mean"],
                "%s / %s" % (f(v["n"], 0), f(v["n_max"], 0) if v["n_max"] else "?"),
                v["r1"], status(v)))
            nums.append((block, ident, r, "mean (%s CI)" % CL, v["mean"],
                         v["mean"] - v["half"], v["mean"] + v["half"], "ns"))
    desc = [(name, d) for _, name, d in configs if d]
    if desc:
        p("")
        for nd in desc:
            p("- *%s*: %s" % nd)
    p("")

p("## Differences\n")
p("Per run; the CI combines the two configurations' CIs.\n")
p("| Difference | block | run | mean, ns | %s CI, ns |\n|---|---|---:|---:|---:|" % CL)
for block, ka, kb, lab in DIFFS:
    for r, (m, h, _) in diff(ka, kb).items():
        p("| %s | %s | %d | %s | %s |" % (lab, block, r, f(m, 1, True), ci(h)))
        nums.append((block, ka[1] + " - " + kb[1], r, "difference (%s CI)" % CL, m,
                     m - h, m + h, "ns"))
for block, sfx in RATIOS:
    a, b = run[("lat", "bench_defended" + sfx)], run[("lat", "bench" + sfx)]
    for r in sorted(set(a) & set(b)):
        ratio = a[r]["mean"] / b[r]["mean"]
        p("| AoN (defended) / baseline | %s | %d | %.1f× | — |" % (block, r, ratio))
        nums.append((block, "bench_defended%s / bench%s" % (sfx, sfx), r, "ratio", ratio,
                     "", "", ""))
p("")

if R >= 2:
    p("## Across runs\n")
    p("Median of the run means [min–max], and the between-run SD of the means "
      "against their within-run SE: about 1, the runs agree within their own "
      "precision; clearly above 1 (> %g, ⚠), processes differ by more than a run "
      "resolves, and more runs (not longer ones) narrow the result.\n" % DOMINATES)
    p("| Configuration / difference | block | runs | median, ns | [min–max], ns | SD between / SE within |")
    p("|---|---|---:|---:|---:|---:|")
    items = [(block, name, {r: (v["mean"], v["half"], v["se"]) for r, v in run[(sub, i)].items()})
             for sub, block, _, configs in BLOCKS for i, name, _ in configs]
    items += [(block, lab, diff(ka, kb)) for block, ka, kb, lab in DIFFS]
    for block, name, per_run in items:
        if len(per_run) < 2:
            continue
        med, lo, hi, sd_b, se_w = across(per_run)
        ratio = sd_b / se_w if se_w else float("inf")
        p("| %s | %s | %d | %s | [%s–%s] | %.1f%s |" % (
            name, block, len(per_run), f(med), f(lo), f(hi), ratio,
            " ⚠" if ratio > DOMINATES else ""))
        nums.append((block, name, "all", "median over runs (min-max)", med, lo, hi, "ns"))
    p("")
else:
    p("One run: the process-to-process variability is not measured; run "
      "`run_cost.sh` again on the same commit (or with `RUNS=<n>`) to add runs.\n")

with open(os.path.join(out, "cost_numbers.csv"), "w", newline="") as fh:
    w = csv.writer(fh)
    w.writerow(["block", "id", "run", "quantity", "value", "ci_lo", "ci_hi", "unit"])
    w.writerows(nums)
open(os.path.join(out, "COST.md"), "w").write("\n".join(P) + "\n")
print("wrote", os.path.join(out, "COST.md"))
