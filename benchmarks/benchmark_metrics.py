#!/usr/bin/env python
# Copyright 2024 - Benchmark: Python vs Rust Metrics implementations
#
# SPDX-License-Identifier: Apache-2.0
"""Benchmark comparing Python and Rust Metrics implementations.

Runs both implementations against the files in examples/ and against the
bandit/ source tree itself, measuring wall time and throughput (files/sec).

Usage:
    python benchmarks/benchmark_metrics.py
"""
import statistics
import sys
import time
from pathlib import Path

from bandit.core.metrics import Metrics as PyMetrics

try:
    from bandit_metrics import Metrics as RsMetrics
except ImportError:
    sys.exit(
        "ERROR: Rust extension not installed. Run: cd rust/bandit_metrics && maturin develop --release"
    )

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parent.parent
WARMUP_ROUNDS = 3
BENCH_ROUNDS = 10

# Simulated issue scores — representative of a typical bandit finding
SAMPLE_SCORES = [{"SEVERITY": [0, 3, 5, 10], "CONFIDENCE": [1, 0, 5, 0]}]
EMPTY_SCORES = []


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def collect_python_files(directory: Path) -> list[Path]:
    """Recursively collect all .py files under *directory*."""
    return sorted(directory.rglob("*.py"))


def read_file_lines(path: Path) -> list[bytes]:
    """Read a file and return its lines as a list of bytes (matching bandit's API)."""
    try:
        with open(path, "rb") as f:
            return f.readlines()
    except (OSError, PermissionError):
        return []


def run_metrics_pipeline(
    metrics_class, file_data: list[tuple[str, list[bytes]]]
):
    """Run the full Metrics pipeline: begin → count_locs → note_nosec → count_issues → aggregate.

    This mirrors the real bandit pipeline where each file goes through the
    full mutation sequence before aggregation.
    """
    m = metrics_class()
    for fname, lines in file_data:
        m.begin(fname)
        m.count_locs(lines)
        # Simulate nosec annotations (~5% of files)
        if hash(fname) % 20 == 0:
            m.note_nosec(2)
        # Simulate skipped tests (~3% of files)
        if hash(fname) % 33 == 0:
            m.note_skipped_test(1)
        # Simulate issues found (~30% of files)
        if hash(fname) % 3 == 0:
            m.count_issues(SAMPLE_SCORES)
        else:
            m.count_issues(EMPTY_SCORES)
    m.aggregate()
    return m


def benchmark_impl(
    label: str, metrics_class, file_data: list[tuple[str, list[bytes]]]
) -> dict:
    """Benchmark a single implementation over *rounds* iterations.

    Returns a dict with timing statistics.
    """
    num_files = len(file_data)

    # Warmup
    for _ in range(WARMUP_ROUNDS):
        run_metrics_pipeline(metrics_class, file_data)

    # Timed rounds
    times = []
    for _ in range(BENCH_ROUNDS):
        start = time.perf_counter()
        run_metrics_pipeline(metrics_class, file_data)
        elapsed = time.perf_counter() - start
        times.append(elapsed)

    mean_t = statistics.mean(times)
    stdev_t = statistics.stdev(times) if len(times) > 1 else 0.0
    min_t = min(times)
    max_t = max(times)
    throughput = num_files / mean_t if mean_t > 0 else float("inf")

    return {
        "label": label,
        "files": num_files,
        "rounds": BENCH_ROUNDS,
        "mean_ms": mean_t * 1000,
        "stdev_ms": stdev_t * 1000,
        "min_ms": min_t * 1000,
        "max_ms": max_t * 1000,
        "throughput": throughput,
    }


def print_results(results: list[dict], corpus_name: str) -> None:
    """Pretty-print benchmark results for a corpus."""
    print(f"\n{'=' * 72}")
    print(f"  Corpus: {corpus_name}")
    print(f"{'=' * 72}")

    # Header
    print(
        f"  {'Impl':<10} {'Files':>6} {'Mean (ms)':>12} {'StDev (ms)':>12} "
        f"{'Min (ms)':>10} {'Max (ms)':>10} {'Files/sec':>12}"
    )
    print(
        f"  {'-' * 10} {'-' * 6} {'-' * 12} {'-' * 12} {'-' * 10} {'-' * 10} {'-' * 12}"
    )

    for r in results:
        print(
            f"  {r['label']:<10} {r['files']:>6} {r['mean_ms']:>12.3f} {r['stdev_ms']:>12.3f} "
            f"{r['min_ms']:>10.3f} {r['max_ms']:>10.3f} {r['throughput']:>12.1f}"
        )

    # Speedup
    if len(results) == 2:
        py_mean = results[0]["mean_ms"]
        rs_mean = results[1]["mean_ms"]
        if rs_mean > 0:
            speedup = py_mean / rs_mean
            print(f"\n  Speedup (Rust vs Python): {speedup:.2f}x")
        print()


def verify_parity(file_data: list[tuple[str, list[bytes]]]) -> bool:
    """Quick parity check: both implementations must produce identical data."""
    py_m = run_metrics_pipeline(PyMetrics, file_data)
    rs_m = run_metrics_pipeline(RsMetrics, file_data)

    py_data = py_m.data
    rs_data = rs_m.data

    if set(py_data.keys()) != set(rs_data.keys()):
        print(
            f"  PARITY FAIL: key mismatch py={set(py_data.keys())} rs={set(rs_data.keys())}"
        )
        return False

    for fname in py_data:
        py_entry = py_data[fname]
        rs_entry = rs_data[fname]
        if dict(py_entry) != dict(rs_entry):
            print(
                f"  PARITY FAIL for '{fname}': py={dict(py_entry)} rs={dict(rs_entry)}"
            )
            return False

    return True


def run_benchmark_suite(corpus_name: str, directory: Path) -> None:
    """Run the full benchmark suite for a given corpus directory."""
    files = collect_python_files(directory)
    if not files:
        print(f"\n  No .py files found in {directory}")
        return

    # Pre-read all files into memory so I/O doesn't affect timing
    file_data = [(str(f), read_file_lines(f)) for f in files]
    total_lines = sum(len(lines) for _, lines in file_data)

    print(f"\n  Corpus: {corpus_name}")
    print(f"  Directory: {directory}")
    print(f"  Files: {len(file_data)}, Total lines: {total_lines}")
    print(f"  Rounds: {BENCH_ROUNDS} (+ {WARMUP_ROUNDS} warmup)")

    # Parity check first
    print("  Verifying parity... ", end="", flush=True)
    if verify_parity(file_data):
        print("OK")
    else:
        print("FAILED — results may not be comparable")

    # Run benchmarks
    py_result = benchmark_impl("Python", PyMetrics, file_data)
    rs_result = benchmark_impl("Rust", RsMetrics, file_data)

    print_results([py_result, rs_result], corpus_name)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    print("=" * 72)
    print("  Bandit Metrics Benchmark: Python vs Rust (PyO3)")
    print(
        f"  Warmup rounds: {WARMUP_ROUNDS}, Benchmark rounds: {BENCH_ROUNDS}"
    )
    print("=" * 72)

    examples_dir = REPO_ROOT / "examples"
    bandit_dir = REPO_ROOT / "bandit"

    run_benchmark_suite("examples/", examples_dir)
    run_benchmark_suite("bandit/", bandit_dir)

    # Combined corpus
    combined_files = collect_python_files(examples_dir) + collect_python_files(
        bandit_dir
    )
    combined_data = [(str(f), read_file_lines(f)) for f in combined_files]
    total_lines = sum(len(lines) for _, lines in combined_data)

    print(f"\n  Corpus: combined (examples/ + bandit/)")
    print(f"  Files: {len(combined_data)}, Total lines: {total_lines}")

    print("  Verifying parity... ", end="", flush=True)
    if verify_parity(combined_data):
        print("OK")
    else:
        print("FAILED")

    py_result = benchmark_impl("Python", PyMetrics, combined_data)
    rs_result = benchmark_impl("Rust", RsMetrics, combined_data)
    print_results([py_result, rs_result], "combined (examples/ + bandit/)")

    print("Done.")


if __name__ == "__main__":
    main()
