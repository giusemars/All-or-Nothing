# How the evaluation works

The evaluation asks three questions about the defense in
[`defense.md`](defense.md):

- **Correctness**: does a defended program behave like its baseline, and is
  the binary built as designed?
- **Security**: does the module refuse both attack vectors, and does the
  signal rule hold?
- **Cost**: what does a protected call cost, against an unprotected one and
  against seccomp?

Every row compares a **baseline** build (no `.note.aon`, never policed) with
a **defended** build of the same source. Both scripts need root and write to
`evaluation/results/`. No results are included in the repository, so
`RESULTS.md` and `COST.md` exist only after the scripts have run.

| Block | Rows | Command | Summary |
| --- | --- | --- | --- |
| security | C1–C5, S1–S4 | `evaluation/security/run_security.sh` | `RESULTS.md` |
| cost | P0–P3 | `evaluation/cost/run_cost.sh` | `COST.md` |

The row IDs are only labels for this evaluation. They are not the thesis
requirements (B1–B5, D1–D4) or properties (P1–P4) listed in
[`defense.md`](defense.md#requirements).

## Security block

### Rows

| Row | Case | Expected on the defended build |
| --- | --- | --- |
| C1 | `cat` on `victim.txt`, `/etc/services`, 1 MiB random | same stdout and exit as the baseline, no refusal |
| C2 | `sig correctness` | the armed `write` is refused once, then succeeds on retry |
| C3 | verifier, `ud2` census | no stray `ud2` in the AoN region |
| C4 | `.note.aon`, `syscall` census | note present; every aligned `syscall` is an egress gate |
| C5 | linked blocks | only the blocks of the required system calls |
| S1 | `cat aligned` (vector A) | refused (unarmed egress gate), exit 3 |
| S2 | `cat misaligned` (vector B) | refused (outside the AoN region), exit 3 |
| S3 | `sig attack-unarmed` | refused, exit 3 |
| S4 | `sig attack-armed` | refused (disarmed before the handler), exit 3 |

C3–C5 are static, the rest are runs. On the baseline the S rows succeed:
`/bin/echo` replaces the process. The attacks are described in
[`attack.md`](attack.md).

### Steps

1. Record the environment, then `make clean all`.
2. **Static evidence** on the four binaries: `analyze_binary.py` (AoN region,
   ingress gates, every `syscall`, every `0f 05` / `0f 0b` at any offset,
   linked blocks), plus `verify_aon.py`, `readelf -n` and disassembly.
3. Reload `aon_mod`, so its counters and the log start clean.
4. **One representative run** per case (8 rows × 2 builds), keeping stdout,
   stderr, exit status and the `aon:` log lines. A 5 s pause follows each
   run, because the module's log is rate limited.
5. **`REPEAT` more runs** (100) per case, keeping only the outcome, to show
   it is deterministic.
6. **One run under `strace -n -k`** per case: each system call with its
   number and the stack that issued it. strace stops before the module
   refuses, so a refused call shows its original number and `-1 ENOSYS`.
7. `summarize.py` writes `RESULTS.md`.

### How outcomes are judged

From files on disk, not from what the program reports:

| Question | Evidence |
| --- | --- |
| attack succeeded? | `[attacker]` on stdout |
| call refused? | `BLOCKED` in the run's kernel log |
| signal rule fired? | increase of `signal_disarms` |
| C1 output correct? | sha256 of stdout = sha256 of the input |
| every call through a block? | strace count = expected count of open/read/write/close/exit |
| which site issued it? | innermost strace frame |

## Cost block

### What is measured

[`bench.c`](../evaluation/bench/bench.c) loops on the hardened `write`
wrapper, built four ways:

| Build | Policy |
| --- | --- |
| `bench` | none |
| `bench_defended` | `aon_mod` (ingress + egress gate on every call) |
| `bench_seccomp` | seccomp filter on the system call number |
| `bench_seccomp_ip` | the same, plus each number pinned to its wrapper's `syscall` (seccomp's analogue of D4) |

The default call is `write(-1, buf, 0)`, the cheapest real system call, so
the AoN overhead is at its largest relative share (the worst case). Each
`SIZE` in `SIZES` repeats the four builds with real writes of `SIZE` bytes
to a file on tmpfs.

### Rows

| Row | Module | Measures |
| --- | --- | --- |
| P0 | not loaded | TSC calibration; reference costs: timer, `getpid`, `write(-1)`, invalid nr, `int3`, `ud2` |
| P1 | loaded | `bench_defended` − `bench`: the cost of a protected call |
| P2 | loaded | `bench_seccomp*` − `bench`: the same for seccomp |
| P3 | unloaded vs loaded | `bench` (unprotected): what the module costs other processes |

`ud2` − `int3` isolates what is specific to #UD on the machine (e.g. a
hypervisor intercept). The P0 `ud2` goes to a `SIGILL` handler, so it is only
an upper bound on the ingress gate, which the module handles in the kernel.

### Timing

Each call is timed between two serialized TSC reads and streamed to stdout as
ticks. The defended binary cannot call `clock_gettime`: the module would
refuse it, since it is not a required system call. `tsc_calib` converts
ticks to ns. The process is pinned to one CPU.

### Run length: batch means

[`batch_means.py`](../evaluation/cost/batch_means.py) reads each stream until
the estimate is good enough (Law & Kelton):

1. Discard 1000 samples, then take n = 25,600.
2. **Independence**: split them into 400 batches. The lag-1 autocorrelation
   of the batch means must be < 0.2.
3. **Estimate**: split them into 20 batches. The estimate is their mean, with
   a 95% CI.
4. Stop when the batches are independent **and** the CI half-width is
   < 1% of the estimate. Otherwise double n.

Both rules are needed: rare long outliers (preemptions, VM exits) pass the
independence test but widen the CI. A configuration that hits the `MAXN` cap
is reported as *not converged*.

### Results

`analyze_cost.py` writes `COST.md`. It has one row per configuration and run,
and the differences above, each computed within a run, with the two CIs
combined. With several runs it also gives the median [min–max] and the
between-run SD against the within-run SE. A ratio well above 1 means more
runs, not longer ones, are needed. Running `run_cost.sh` again on the same
commit adds runs to the same directory.

## Not covered

- **Real attacks**: the attacker is simulated ([`attack.md`](attack.md)), so S1–S4 show what the module
  does with a hijacked thread, not that a real exploit reaches that state.
- **Whole-wrapper reuse** through the ingress gate: arguments are not
  validated by design.
- **The other limits** in
  [`defense.md`](defense.md#what-the-defense-does-not-cover).
- **Other machines**: one VM, one kernel. Cost depends on the CPU and the
  hypervisor, both recorded in `environment.txt`.

Details, settings and output files: [`../evaluation/security/README.md`](../evaluation/security/README.md),
[`../evaluation/cost/README.md`](../evaluation/cost/README.md).
