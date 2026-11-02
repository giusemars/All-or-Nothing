# How the evaluation works

The evaluation asks three questions about the defense in
[`defense.md`](defense.md):

- **Correctness**: does a defended program behave like its baseline, and is
  the binary built as designed?
- **Security**: does the module refuse both attack vectors, and does the
  signal rule hold?
- **Cost**: what does a protected call cost, against an unprotected one and
  against seccomp?

They are answered with three programs, the [scenarios](#scenarios). Each is
built twice from the same source: a **baseline** build (no `.note.aon`, never
policed) and a **defended** build. The [experiments](#experiments) run them
and compare the two builds. They are split into two blocks, each run by one
script:

| Block                                                           | Scenarios    | Rows         | Command                               | Summary      |
| --------------------------------------------------------------- | ------------ | ------------ | ------------------------------------- | ------------ |
| [correctness and security](#correctness-and-security-c1c5-s1s4) | `cat`, `sig` | C1–C5, S1–S4 | `evaluation/security/run_security.sh` | `RESULTS.md` |
| [cost](#cost-p0p3)                                              | `bench`      | P0–P3        | `evaluation/cost/run_cost.sh`         | `COST.md`    |

Both scripts are run from the repository top, need root (they load and
unload `aon_mod`) and write to `evaluation/results/`. No results are included
in the repository.

The row IDs are only labels. They are not the thesis requirements (B1–B5,
D1–D4) or properties (P1–P4) of [`defense.md`](defense.md#requirements).

## Scenarios

### `cat`

[`user/cat/`](../user/cat/) is a minimal `cat`: it opens a file, reads it,
writes it to stdout and closes it, so its intended system calls are `open`,
`read`, `write`, `close` and `exit`. Any operand is catted, except two that
instead hijack the thread to invoke `execve` (nr 59), which `cat` never uses:

| Operand      | What runs                                                                    |
| ------------ | ---------------------------------------------------------------------------- |
| a file name  | the real `cat`                                                               |
| `aligned`    | vector A: jump onto the `syscall` of the read wrapper, past its ingress gate |
| `misaligned` | vector B: jump onto a `0f 05` hidden inside `benign_compute`                 |

How the two vectors are built is in [`attack.md`](attack.md).

### `sig`

[`user/signal/`](../user/signal/) exercises the **signal rule**: the module
disarms a thread before running a handler, and `rt_sigreturn` never re-arms
it. In each operand a `SIGTRAP` handler runs while the thread is inside the
`write` block or in ordinary code:

| Operand          | The handler…                                                                   |
| ---------------- | ------------------------------------------------------------------------------ |
| `correctness`    | does nothing, while the thread is armed in `write`                             |
| `attack-unarmed` | reuses the read egress gate for `execve`, from ordinary code                   |
| `attack-armed`   | reuses the read egress gate for `execve`, while the thread is armed in `write` |

The thread is armed for only one instruction (the body's `movl`), so `sig`
**single-steps** the `write` (`EFLAGS.TF`) to land a `SIGTRAP` there on every
run. The handler recognizes the egress gate by its opcode (`0f 05` near
`__aon_write`), since the baseline has no `ud2` and the offset differs, and
stops stepping by clearing TF in the saved context. `UC_RIP` and `UC_EFL` in
`sig.c` are hard-coded because nolibc has no `ucontext_t`. `sig` never calls
`read()`: its read block is linked only because `sig.c` references
`sys_read_egress`.

### `bench`

[`bench.c`](../evaluation/bench/bench.c) has no attack: it loops on the
hardened `write` wrapper. Besides the two usual builds, it is built with two
seccomp policies for comparison:

| Build              | Policy                                                                                  |
| ------------------ | --------------------------------------------------------------------------------------- |
| `bench`            | none                                                                                    |
| `bench_defended`   | `aon_mod` (ingress + egress gate on every call)                                         |
| `bench_seccomp`    | seccomp filter on the system call number                                                |
| `bench_seccomp_ip` | the same, plus each number pinned to its wrapper's `syscall` (seccomp's analogue of D4) |

- **The call.** By default it is `write(-1, buf, 0)`, the cheapest real
  system call, so the AoN overhead is at its largest share (the worst case).
  With a `SIZE`, every call is a real write of `SIZE` bytes to a sink file.
- **Real writes.** The sink is opened and truncated before the seccomp filter
  and before any measurement. When the next write would grow it past
  `MAX_FILE_SIZE`, the hardened `lseek` wrapper rewinds it, outside the timed
  window, so every sample is one `write`. The default sink is on tmpfs, so a
  write is a copy into the page cache; a disk filesystem would add writeback
  and journal outliers.

## Experiments

### Correctness and security (C1–C5, S1–S4)

| Row | Scenario, operand                                    | Baseline                                        | Defended, module loaded                                 |
| --- | ---------------------------------------------------- | ----------------------------------------------- | ------------------------------------------------------- |
| C1  | `cat` on `victim.txt`, `/etc/services`, 1 MiB random | prints the file, exit 0                         | same stdout and exit, no refusal                        |
| C2  | `sig correctness`                                    | first write allowed, *not demonstrated*, exit 1 | first write refused (`-ENOSYS`), retry succeeds, exit 0 |
| C3  | static: verifier, `ud2` census                       | —                                               | no stray `ud2` in the AoN region                        |
| C4  | static: `.note.aon`, `syscall` census                | —                                               | note present; every aligned `syscall` is an egress gate |
| C5  | static: linked blocks                                | —                                               | only the blocks of the required system calls            |
| S1  | `cat aligned` (vector A)                             | `execve` runs                                   | refused (unarmed egress gate), exit 3                   |
| S2  | `cat misaligned` (vector B)                          | `execve` runs                                   | refused (outside the AoN region), exit 3                |
| S3  | `sig attack-unarmed`                                 | `execve` runs                                   | refused, exit 3                                         |
| S4  | `sig attack-armed`                                   | `execve` runs                                   | refused (disarmed before the handler), exit 3           |

What each row shows:

- **C1**: the defense changes nothing for intended behavior.
- **C2**: the cost of the signal rule. The interrupted block is refused and
  must be run again, here exactly once; under a real signal load, such as a
  timer, it happens at random, so a real program must retry every call on a
  path a signal can reach.
- **C3–C5**: the binaries are built as designed. They inspect the binaries
  of both scenarios (`cat`, `cat_defended`, `sig`, `sig_defended`), with the
  verifier, the note and the linked blocks checked on the two defended ones.
  C5 also shows `sig`'s read block, linked only for `sys_read_egress`.
- **S1, S2**: the two code-reuse vectors are refused. When `execve` runs on
  the baseline, `/bin/echo` replaces the process.
- **S3, S4**: a handler is always unarmed, even when it interrupts an armed
  thread. S4 is the case that matters: if the arming carried into the
  handler, the `execve` would run.

Outcomes are judged from files on disk, not from what the program reports:

| Question                    | Evidence                                                    |
| --------------------------- | ----------------------------------------------------------- |
| attack succeeded?           | `[attacker]` on stdout                                      |
| call refused?               | `BLOCKED` in the run's kernel log                           |
| signal rule fired?          | increase of `signal_disarms`                                |
| C1 output correct?          | sha256 of stdout = sha256 of the input                      |
| every call through a block? | strace count = expected count of open/read/write/close/exit |
| which site issued it?       | innermost strace frame                                      |

#### Running it

```bash
evaluation/security/run_security.sh [outdir]
```

The script ([`run_security.sh`](../evaluation/security/run_security.sh)):

1. records the environment, then runs `make clean all`;
2. collects **static evidence** (C3–C5) on the four binaries:
   [`analyze_binary.py`](../evaluation/security/analyze_binary.py) (AoN
   region, ingress gates, every `syscall`, every `0f 05` / `0f 0b` at any
   offset, linked blocks, as JSON), plus `verify_aon.py`, `readelf -n` and
   disassembly;
3. reloads `aon_mod`, so its counters and the log start clean;
4. runs each case once as the **representative run** (8 rows × 2 builds),
   keeping stdout, stderr, exit status and the `aon:` log lines, with a 5 s
   pause after each because the module's log is rate limited;
5. runs each case `REPEAT` more times (100), keeping only the outcome, to
   show it is deterministic;
6. runs each case once under `strace -n -k`: every system call with its
   number and the stack that issued it. strace reports before the module
   refuses, so a refused call shows its original number and `-1 ENOSYS`;
7. writes `RESULTS.md` with [`summarize.py`](../evaluation/security/summarize.py).

Results go to `evaluation/results/<date>/` unless `outdir` is given. The
environment variable `REPEAT` changes the number of repeats. The script uses
`sudo` for `insmod`, `rmmod` and `dmesg`; run it as root to avoid that, or
set `AON_SUDO` to another command. To write `RESULTS.md` again without
running anything:

```bash
python3 evaluation/security/summarize.py evaluation/results/<dir> > evaluation/results/<dir>/RESULTS.md
```

### Cost (P0–P3)

| Row | Module             | Measures                                                                                  |
| --- | ------------------ | ----------------------------------------------------------------------------------------- |
| P0  | not loaded         | TSC calibration; reference costs: timer, `getpid`, `write(-1)`, invalid nr, `int3`, `ud2` |
| P1  | loaded             | `bench_defended` − `bench`: the cost of a protected call                                  |
| P2  | loaded             | `bench_seccomp*` − `bench`: the same for seccomp                                          |
| P3  | unloaded vs loaded | `bench` (unprotected): what the module costs other processes                              |

P1 and P2 are measured once with `write(-1, buf, 0)` and once per nonzero
`SIZE` in `SIZES`; the AoN cost is fixed per call, so its share falls as
`SIZE` grows. In P0, `ud2` − `int3` isolates what is specific to #UD on the
machine, such as a hypervisor intercept; the P0 `ud2` goes to a `SIGILL`
handler, so it is only an upper bound on the ingress gate, which the module
handles in the kernel.

#### How each value is obtained

**Timing.** Each call is timed between two serialized TSC reads and
streamed to stdout as ticks; `tsc_calib` converts ticks to ns, and the
process is pinned to one CPU. The defended binary cannot call
`clock_gettime`, because the module would refuse it (it is not a required
system call). The `nop` configuration, two TSC reads with nothing between
them, is the cost of the timer itself, which every other value, P0 included,
contains.

**Run length: batch means.**
[`batch_means.py`](../evaluation/cost/batch_means.py) reads each stream until
the estimate is good enough (Law & Kelton):

1. Discard 1000 samples, then take n = 25,600.
2. **Independence**: split them into 400 batches. The lag-1 autocorrelation
   of the batch means must be < 0.2.
3. **Estimate**: split them into 20 batches. The estimate is their mean, with
   a 95% CI.
4. Stop when the batches are independent **and** the CI half-width is
   < 1% of the estimate. Otherwise double n, up to the `MAXN` cap; a
   configuration that reaches it is reported as *not converged*.

Both rules are needed: rare long outliers (preemptions, VM exits) pass the
independence test but widen the CI.

**Results.** `COST.md` has one row per configuration and run, then the
differences P1–P3, each computed within a run with the two CIs combined.
With several runs it adds the median [min–max] and the ratio of between-run
SD to within-run SE: well above 1 means more runs, not longer ones, are
needed.

#### Running it

```bash
evaluation/cost/run_cost.sh [config]
```

[`run_cost.sh`](../evaluation/cost/run_cost.sh) reads
[`cost.conf`](../evaluation/cost/cost.conf), builds the benchmark and the
module, runs P0
([`tsc_calib.c`](../evaluation/cost/tsc_calib.c),
[`syscall_latency.c`](../evaluation/cost/syscall_latency.c)), then P1–P3
with the [bench](../evaluation/bench/) builds, each configuration under
batch means, and finally [`analyze_cost.py`](../evaluation/cost/analyze_cost.py).

Results go to `evaluation/results/cost-<branch>-<commit>/`. Running again on
the same commit appends runs to that directory, so `RUNS=4
evaluation/cost/run_cost.sh` adds four. Any setting can be overridden from
the environment like that, or put in another file passed as `config` (keys
it leaves out take the defaults). To analyze a directory again without
measuring:

```bash
python3 evaluation/cost/analyze_cost.py evaluation/results/cost-<branch>-<commit>
```

Settings in `cost.conf`, with their defaults (`COST.md` states the values
used):

| Setting                                             | Default                         | Meaning                                                                                                         |
| --------------------------------------------------- | ------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| `OUT`                                               | empty                           | results directory; empty = `evaluation/results/cost-<branch>-<commit>`                                          |
| `RUNS`                                              | 1                               | runs made by this invocation (a run = P0–P3 once)                                                               |
| `GAMMA`                                             | 0.01                            | target relative CI half-width (5% was too wide for the seccomp and module-idle differences, 7–27 ns on ~450 ns) |
| `MAXN` / `MAXN_DEFENDED`                            | 32 Mi / 8 Mi                    | call cap of a configuration; the second for `bench_defended` and P0 `ud2` (~20 µs per call)                     |
| `CPU`                                               | 2                               | CPU the measured processes are pinned to                                                                        |
| `OWNER`                                             | empty                           | `uid:gid` that gets the results; empty = who ran the script                                                     |
| `QUIET`                                             | 1                               | seconds of pause before each configuration                                                                      |
| `SIZES`                                             | `0 64 4096 65536`               | P1/P2 write sizes (at most 1 MiB); 0 = `write(-1, buf, 0)`                                                      |
| `SINK`                                              | `/dev/shm/aon_bench`            | file the real writes go to                                                                                      |
| `MAX_FILE_SIZE`                                     | 1048576                         | size at which the sink is rewound                                                                               |
| `WARMUP`, `N0`, `K_TEST`, `K_FINAL`, `RHO`, `ALPHA` | 1000, 25600, 400, 20, 0.2, 0.05 | batch-means inputs; empty = `batch_means.py`'s default                                                          |

A run takes about 30 s when every configuration converges early. Each
configuration that reaches its cap adds up to ~15 s (~3 min for
`bench_defended` and `ud2`), and each nonzero `SIZE` adds the four builds
again.

Output besides `COST.md`:

- `cost_numbers.csv`, and `per_run.csv` with one line per run and
  configuration;
- one `.json` per configuration: all `analyze_cost.py` needs;
- `environment.txt`, to which each invocation appends CPU, hypervisor, sizes
  and the sink's filesystem (`COST.md` warns when runs come from different
  builds);
- the raw TSC samples (`*.bin`, up to 128 MiB each), which are not committed;
  while they are there, `per_run.csv` also has percentiles.

## Not covered

- **Real attacks**: the attacker is simulated ([`attack.md`](attack.md)), so
  S1–S4 show what the module does with a hijacked thread, not that a real
  exploit reaches that state.
- **Whole-wrapper reuse** through the ingress gate: arguments are not
  validated by design.
- **The other limits** in
  [`defense.md`](defense.md#what-the-defense-does-not-cover).
- **Other machines**: one VM, one kernel. Cost depends on the CPU and the
  hypervisor, both recorded in `environment.txt`.
