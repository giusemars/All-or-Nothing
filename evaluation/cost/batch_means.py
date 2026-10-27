#!/usr/bin/env python3
"""batch_means.py - run length and confidence interval of a steady-state mean
by batch means (Law & Kelton).

  batch_means.py [options] -- <command> [args...]

  --warmup D    observations discarded first (1000)
  --n N         initial n, a multiple of K_TEST and K_FINAL (25600)
  --k-test K    batches of the independence test (400)
  --k-final K   batches of the confidence interval (20)
  --rho R       rho*: max lag-1 autocorrelation of the test batch means (0.2)
  --alpha A     1 - confidence level of the CI (0.05: 95% CI)
  --gamma G     target relative half-width of the CI (0.01)
  --max NMAX    cap on n (32 Mi)
  --out PREFIX  write PREFIX.bin and PREFIX.json

<command> is the model: a process that writes an endless stream of
observations to its stdout, raw native-endian uint32 (e.g. `bench stream`,
one TSC tick delta per call). One call of the model = the next m observations
of that stream, continuing from where the process is.

  BatchMeans(model, d, n, K_TEST, K_FINAL, RHO_STAR, ALPHA, gamma)
    1-3   run d observations and discard them (warm-up), then n more: Y1..Yn
    repeat
    4-6     independence: split Y into K_TEST batches, r1 = lag-1
            autocorrelation of their batch means
    7-10    interval: split Y into K_FINAL batches; estimate = mean of the
            batch means, (1 - ALPHA) CI half-width
            h = t(1 - ALPHA/2, K_FINAL - 1) * S / sqrt(K_FINAL),
            S the standard deviation of the batch means
    11      stop if r1 < RHO_STAR (batches about independent) and
            h < gamma * |estimate| (relative precision reached)
    12-13   else run n more observations and double n
    output  estimate +- h, batch size b, K_FINAL, r1

Independence alone does not bound the width of the CI: a few long outliers
(a preemption, a VM exit) raise single batch means without correlating them,
so r1 passes while h stays wide. The relative-precision rule (Law & Kelton's
sequential procedure) runs on until the CI is narrow enough.

The procedure itself has no bound on n; NMAX is a safety cap: when doubling
would exceed it, the run stops with `converged` false (`independent` and
`precise` say which test was not met).

Output: one summary line on stdout; with --out, PREFIX.bin (the retained
observations Y1..Yn, uint32) and PREFIX.json (the summary). Units are those
of the observations.
"""
import argparse
import json
import math
import subprocess
import sys

import numpy as np
from scipy import stats

K_TEST, K_FINAL, RHO_STAR, ALPHA = 400, 20, 0.2, 0.05
GAMMA = 0.01  # target relative half-width of the CI
WARMUP, N0, NMAX = 1000, K_TEST * 64, 1 << 25


def lag1(y):
    """Lag-1 autocorrelation of y (0 when every value is equal)."""
    dev = y - y.mean()
    c0 = float((dev * dev).sum())
    return float((dev[1:] * dev[:-1]).sum()) / c0 if c0 else 0.0


def batch_means_of(y, k):
    """The k batch means of y, and the batch size b = len(y) / k."""
    b = len(y) // k
    return y[:k * b].reshape(k, b).mean(axis=1, dtype=np.float64), b


def interval(y, k=K_FINAL, alpha=ALPHA):
    """Steps 11-14: estimate, CI half-width, standard error, batch size."""
    ybar, b = batch_means_of(y, k)
    se = float(ybar.std(ddof=1)) / math.sqrt(k)
    return float(ybar.mean()), float(stats.t.ppf(1 - alpha / 2, k - 1)) * se, se, b


def batch_means(model, d=WARMUP, n=N0, gamma=GAMMA, k_test=K_TEST, k_final=K_FINAL,
                rho_star=RHO_STAR, alpha=ALPHA, n_max=NMAX):
    if n % k_test or n % k_final:
        raise ValueError("n must be a multiple of k_test and k_final")

    n0 = n

    # -- gather the data
    model(d)                                    # warm-up, discarded
    y = model(n)

    while True:
        # -- check batch independence
        rho1 = lag1(batch_means_of(y, k_test)[0])
        # -- build the confidence interval
        est, h, se, b = interval(y, k_final, alpha)
        # -- stop when independent and precise enough (or at the cap)
        independent, precise = rho1 < rho_star, h < gamma * abs(est)
        if (independent and precise) or 2 * n > n_max:
            break
        y = np.concatenate([y, model(n)])
        n *= 2

    return y, dict(estimate=est, half_width=h, rel_half_width=h / abs(est) if est else math.inf,
                   se=se, batch_size=b, r1=rho1, n=n, independent=independent, precise=precise,
                   converged=independent and precise,
                   # the inputs, so a result says how it was obtained
                   warmup=d, n0=n0, k_test=k_test, k_final=k_final, rho_star=rho_star,
                   alpha=alpha, gamma=gamma, n_max=n_max)


def process_model(proc):
    """model(m): the next m uint32 observations from proc's stdout."""
    def model(m):
        buf = proc.stdout.read(4 * m)
        if len(buf) != 4 * m:
            raise RuntimeError("the model stopped after %d bytes" % len(buf))
        return np.frombuffer(buf, dtype=np.uint32)
    return model


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--warmup", type=int, default=WARMUP, help="d (%(default)s)")
    ap.add_argument("--n", type=int, default=N0, help="initial n (%(default)s)")
    ap.add_argument("--k-test", type=int, default=K_TEST,
                    help="batches of the independence test (%(default)s)")
    ap.add_argument("--k-final", type=int, default=K_FINAL,
                    help="batches of the confidence interval (%(default)s)")
    ap.add_argument("--rho", type=float, default=RHO_STAR,
                    help="rho*: max lag-1 autocorrelation (%(default)s)")
    ap.add_argument("--alpha", type=float, default=ALPHA,
                    help="1 - confidence level of the CI (%(default)s)")
    ap.add_argument("--gamma", type=float, default=GAMMA,
                    help="target relative CI half-width (%(default)s)")
    ap.add_argument("--max", type=int, default=NMAX, help="cap on n (%(default)s)")
    ap.add_argument("--out", help="write PREFIX.bin and PREFIX.json")
    ap.add_argument("command", nargs="+")
    a = ap.parse_args()
    if a.n % a.k_test or a.n % a.k_final:
        ap.error("--n must be a multiple of --k-test and --k-final")

    proc = subprocess.Popen(a.command, stdout=subprocess.PIPE)
    try:
        y, res = batch_means(process_model(proc), a.warmup, a.n, a.gamma, a.k_test,
                             a.k_final, a.rho, a.alpha, a.max)
    finally:
        proc.kill()
        proc.wait()

    if a.out:
        y.astype(np.uint32).tofile(a.out + ".bin")
        with open(a.out + ".json", "w") as fh:
            json.dump(res, fh, indent=1)
    print("estimate=%.4f half_width=%.4f rel=%.4f batch_size=%d k_final=%d r1=%.4f n=%d "
          "independent=%d precise=%d converged=%d"
          % (res["estimate"], res["half_width"], res["rel_half_width"], res["batch_size"],
             res["k_final"], res["r1"], res["n"], res["independent"], res["precise"],
             res["converged"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
