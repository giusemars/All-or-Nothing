# Requirements

## Python

**Python 3.7 or newer**, for the Python scripts of the repository:

| Script | Needs |
| --- | --- |
| `tools/verify_aon.py` (build-time verifier, run on every defended build) | standard library only (`dataclasses`: 3.7) |
| `evaluation/security/analyze_binary.py`, `evaluation/security/summarize.py` | standard library only (`subprocess.run(capture_output=...)`: 3.7) |
| `evaluation/cost/batch_means.py`, `evaluation/cost/analyze_cost.py` | `numpy`, `scipy` (`scipy.stats`) |

The cost evaluation is the only part that needs third-party packages; it was
run with numpy 2.2.4 and scipy 1.15.3 (Debian `python3-numpy`,
`python3-scipy`) on Python 3.13.
