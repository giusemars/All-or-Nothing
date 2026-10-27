# Correctness and security evaluation (rows C1–C5, S1–S4)

Does the defended build behave like the baseline, and does the module refuse
both attack vectors?

| File | Role |
| --- | --- |
| `run_security.sh` | the one command: clean build of everything (`make all` at the top), static evidence, then every dynamic case with `aon_mod` freshly loaded; writes the raw files and runs `summarize.py` |
| `analyze_binary.py` | static evidence on one linked binary (JSON): AoN region and ingress gates, aligned `syscall`s, `0f 05` and `0f 0b` pairs at any offset (aligned / misaligned, inside / outside the AoN region), which AoN blocks were linked |
| `summarize.py` | writes `RESULTS.md` from a results directory |

Run it from the repository top (it uses `sudo` for `insmod` / `rmmod` /
`dmesg`; set `AON_SUDO` to use another command, or run it as root):

```bash
evaluation/security/run_security.sh
```

Results go to `evaluation/results/<date>/` (or the directory passed as the
argument), summary in `RESULTS.md`. `REPEAT` (100) sets how many times each
dynamic case is repeated after its representative run. Re-summarize without
running:

```bash
python3 evaluation/security/summarize.py evaluation/results/<dir> > evaluation/results/<dir>/RESULTS.md
```

`evaluation/results/final_run-a696bed` is the recorded run (made when the
script was still `evaluation/run_eval.sh`).

## Rows

- **C1**: `cat` on three files (`victim.txt`, a text file, 1 MiB random),
  baseline vs defended: same stdout and exit status, no refusals.
- **C2**: `sig correctness`: a signal while the thread is armed refuses that
  block's egress gate and the caller retries.
- **C3, C4, C5** (static, on `cat_defended` and `sig_defended`): the verifier
  passes and no stray `ud2` is in the AoN region; the `.note.aon`; the census
  of `syscall` / `0f 05` sites; only the blocks of the required system calls
  are linked.
- **S1, S2**: `cat aligned` / `cat misaligned` (vector A / B).
- **S3, S4**: `sig attack-unarmed` / `attack-armed`: a handler reusing the read
  egress gate for `execve`.

Every dynamic case runs once as the representative run (stdout, stderr, exit
status and the `aon:` kernel log lines kept verbatim), then `REPEAT` more times
to show the outcome is deterministic, and once more under `strace -n -k`.
