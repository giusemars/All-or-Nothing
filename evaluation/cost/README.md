# Cost evaluation (rows P0–P3)

The cost block of the chosen evaluation set: what a protected call costs, how it
compares with seccomp, and what the module costs processes it does not protect.

| File | Role |
| --- | --- |
| `../../user_aonlibc_bench/` | the benchmark scenario: a loop of calls to the hardened `write` wrapper (`write(-1, buf, 0)`, or real writes of `SIZE` bytes to a file), built as `bench` (baseline), `bench_defended` (AoN blocks), `bench_seccomp` (filter on the number), `bench_seccomp_ip` (number + instruction pointer) |
| `tsc_calib.c` | P0 TSC calibration (ticks/ns against `CLOCK_MONOTONIC`), used to convert every sample of the run to ns |
| `syscall_latency.c` | P0 reference costs (glibc, pulled back from `9th_run`), `syscall_latency <op>` streams one TSC-timed operation per sample: timer, null / `write(-1)` / invalid-nr system call, `ud2`+SIGILL, `int3`+SIGTRAP |
| `cost.conf` | the settings of a run: results directory, runs, call caps, CPU, owner, pause, write sizes and their sink file, and the batch-means inputs (d, first n, k_test, k_final, ρ*, α, γ) |
| `run_cost.sh` | the one command: reads `cost.conf`, runs everything as root (through sudo) into `evaluation/results/cost-<branch>-<commit>/` (on an existing directory it appends runs), then `analyze_cost.py` |
| `batch_means.py` | the batch-means procedure (Law & Kelton) on one configuration: reads a stream (`bench stream`, `syscall_latency <op>`) until the batch means are about uncorrelated and the CI is within `--gamma` (1%) of the estimate, writes the retained samples and the estimate ± CI (95% by default); every input is an option (`--help`) and is recorded in the `.json` |
| `analyze_cost.py` | writes `COST.md` (one row per configuration and run: mean, CI, n, convergence; then the differences and, with several runs, the comparison of runs), `cost_numbers.csv` and `per_run.csv` |

Run everything (it asks for sudo; from under a minute to several, see below) and read
`evaluation/results/cost-<branch>-<commit>/COST.md`:

```bash
evaluation/cost/run_cost.sh
```

Run it again on the same commit to add runs to the same results, several at
once with `RUNS`:

```bash
RUNS=4 evaluation/cost/run_cost.sh
```

Settings are in `cost.conf`; any of them can be overridden from the
environment as above, or put in another file passed as the argument
(`run_cost.sh my.conf`; keys it leaves out take the defaults). Re-analyze a
results directory without measuring:

```bash
python3 evaluation/cost/analyze_cost.py evaluation/results/cost-<branch>-<commit>
```

`evaluation/results/cost-final_run-f876330` is one run with the defaults
(`GAMMA=0.01`: 5% was too wide for the seccomp and module-idle differences,
7–27 ns on ~450 ns). Its `COST.md` lists the configurations that did not
converge.

Settings (`cost.conf`): `OUT` (results directory; empty =
`evaluation/results/cost-<branch>-<commit>`), `RUNS` (1), `GAMMA` (0.01:
target relative half-width of each CI), `MAXN` / `MAXN_DEFENDED` (32 Mi /
8 Mi, the latter for `bench_defended` and P0 `ud2`, ~20 µs per call: call
cap of a configuration, reached = "not converged"), `CPU` (measured process,
2), `OWNER` (gets the results; empty = who ran the script), `QUIET` (1 s
pause before each configuration), `SIZES` / `SINK` / `MAX_FILE_SIZE` (the
P1/P2 write sizes, `0 64 4096 65536`; the file real writes go to,
`/dev/shm/aon_bench`; the size it is rewound at, 1 MiB), and the batch-means inputs `WARMUP` (d,
1000), `N0` (first n, 25,600, a multiple of the two batch counts), `K_TEST`
(400), `K_FINAL` (20), `RHO` (ρ*, 0.2), `ALPHA` (0.05: 95% CI); left empty,
one of these takes `batch_means.py`'s default. `COST.md` states the values
used. A run takes
about 30 s when every configuration converges early; one that reaches its
cap adds up to ~15 s (~3 min for `bench_defended` or `ud2`). Each write size
in `SIZES` besides 0 adds the four P1/P2 builds again. Each invocation
appends its environment to `environment.txt`; `COST.md` warns when the runs
come from different builds.

## Measurements

- **P0**: with the module not loaded, first the TSC calibration
  (`tsc_calib`), used to convert every sample of the run to ns; then the
  reference costs, each operation timed on its own with the TSC like the
  benchmark calls (so each includes the timer) and run under batch means
  like every other configuration. `ud2` − `int3` (same signal path,
  different exception vector) isolates what is specific to #UD on the
  machine, e.g. a hypervisor intercept: the part of the ingress gate's cost
  the kernel cannot see.
- **P1 / P2 (`bench stream`)**: in-program, every call between two
  serialized TSC reads, for the four builds. The defended binary cannot call
  `clock_gettime`: it is not one of its required system calls, so a
  `syscall` for it would be refused. `nop` is the same pair of TSC reads with
  no call between them (the timer's overhead).
- **P1/P2 with real writes (`bench stream SIZE SINK MAX`)**: the same four
  builds once per `SIZE` > 0 in `SIZES` (`cost.conf`, default
  `0 64 4096 65536`; 0 is the `write(-1, buf, 0)` above, at most 1 MiB):
  every call writes `SIZE` bytes to the file `SINK`, opened and truncated by
  the benchmark before its seccomp filter and before any measurement. Once
  the next write would grow the file past `MAX_FILE_SIZE` (1 MiB), the
  hardened `lseek` wrapper rewinds it to 0, outside the timed window, so
  every sample is one `write` of `SIZE` bytes and the file stays small. The
  default `SINK` is on tmpfs (`/dev/shm/aon_bench`): the write is a copy
  into the page cache, without the writeback, journal commits and stable-page
  waits a disk filesystem adds as outliers; point `SINK` at a disk
  filesystem for that data point. The AoN cost is fixed per call, so the
  relative overhead falls as `SIZE` grows. Results:
  `lat/<build>.s<SIZE>.r<k>`, one P1/P2 table and set of differences per
  `SIZE` in `COST.md`; `environment.txt` records the sizes and the sink's
  filesystem.
- **P3**: the baseline `bench stream` (never protected) with the module not
  loaded and loaded but idle: what the module's hooks cost a process they do
  not protect.

- **Run length and estimate: batch means** (`batch_means.py`, here with
  its default inputs). After 1000 warm-up calls, n samples are taken (first n: 25,600). They are split into
  400 batches for the independence test (lag-1 autocorrelation of the batch
  means < 0.2) and into 20 batches for the estimate: the mean of the batch
  means, with a 95% CI t(0.975, 19) · S / √20, S the standard deviation of
  the batch means. n doubles until both the batch means are about
  independent and the CI half-width is below `GAMMA` (1%) of the estimate:
  independence alone lets a few long outliers (preemptions, VM exits)
  through with a wide CI, since they raise single batch means without
  correlating them.
- **Presentation and runs**: `COST.md` shows the data as gathered, one row
  per configuration and run (mean, CI, n, ρ̂1, converged), then the
  differences per run (their CI combines the two CIs). One run = one
  process, so its CI says how precisely that process's value is known, not
  whether the process was a typical one. With several runs `COST.md` adds
  the median of the run means [min–max] and compares the between-run SD
  with the within-run SE: clearly above 1, more runs (not longer runs)
  narrow the result.

A run makes P0 once, then every configuration once, back to back. Raw TSC
samples (`*.bin`, uint32 ticks, up to 128 MiB each) are not committed:
`analyze_cost.py` needs only the `.json` files, and `per_run.csv` keeps one
summary line per run and configuration (with percentiles while the `.bin`
are there).
