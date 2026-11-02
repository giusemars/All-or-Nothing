# Evaluation

Two blocks, each with its own command and README; both write into `results/`.
`bench/` is the benchmark program the cost block times (no attack).

| Directory | Rows | Command (from the repository top) | Summary |
| --- | --- | --- | --- |
| [`security/`](security/README.md) | C1–C5 correctness, S1–S4 security | `evaluation/security/run_security.sh` | `RESULTS.md` |
| [`cost/`](cost/README.md) | P0–P3 cost | `evaluation/cost/run_cost.sh` | `COST.md` |
| [`bench/`](bench/Makefile) | — | built by `cost/run_cost.sh` | — |
| `results/` | output of the two scripts, one directory per run; not part of the repository, so it is empty until you run them | | |

Both need root (they load and unload `aon_mod`) and go through `sudo`.
