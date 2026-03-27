#!/usr/bin/env python3
"""
pin0ccsAI — Test Runner

Runs all test suites in tests/ and reports results.
No pytest required — pure stdlib.

Usage:
  python tests/run_tests.py
  python tests/run_tests.py --verbose
  python tests/run_tests.py --suite payload_cache
"""
from __future__ import annotations

import argparse
import importlib.util
import inspect
import os
import sys
import time
import traceback
from pathlib import Path

# Ensure project root is importable
sys.path.insert(0, str(Path(__file__).parent.parent))

SUITES = [
    "tests/test_models.py",
    "tests/test_payload_cache.py",
    "tests/test_llm_budget.py",
    "tests/test_database.py",
    "tests/test_tester_heuristics.py",
    "tests/test_auth_session.py",
    "tests/test_checkpoint.py",
    "tests/test_learning_loop.py",
    "tests/test_stored_xss.py",
    "tests/test_exploit_memory.py",
    "tests/test_model_lifecycle.py",
    "tests/test_config.py",
    "tests/test_generator.py",
    "tests/test_plugins.py",
]


def load_test_functions(path: str) -> list[tuple[str, callable]]:
    """Load all test_* functions from a test file."""
    spec = importlib.util.spec_from_file_location("_test_module", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return [
        (name, fn)
        for name, fn in inspect.getmembers(module, inspect.isfunction)
        if name.startswith("test_")
    ]


def run_suite(path: str, verbose: bool = False) -> tuple[int, int, list[str]]:
    """
    Run one test file.
    Returns (passed, failed, list_of_failure_messages).
    """
    passed = 0
    failed = 0
    failures: list[str] = []

    try:
        tests = load_test_functions(path)
    except Exception as e:
        return 0, 1, [f"LOAD ERROR in {path}: {e}"]

    suite_name = Path(path).stem
    if verbose:
        print(f"\n{'─'*50}")
        print(f" Suite: {suite_name}  ({len(tests)} tests)")
        print(f"{'─'*50}")

    for name, fn in tests:
        try:
            fn()
            passed += 1
            if verbose:
                print(f"  ✓  {name}")
        except Exception as e:
            failed += 1
            tb = traceback.format_exc()
            msg = f"  ✗  {name}\n     {e}\n{tb}"
            failures.append(msg)
            if verbose:
                print(f"  ✗  {name}")
                print(f"     {e}")

    return passed, failed, failures


def main():
    parser = argparse.ArgumentParser(description="pin0ccsAI test runner")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Print each test name as it runs")
    parser.add_argument("--suite", "-s", default=None,
                        help="Run only suites matching this substring "
                             "(e.g. 'cache', 'budget', 'models')")
    args = parser.parse_args()

    root = Path(__file__).parent.parent
    suites = [str(root / s) for s in SUITES]

    if args.suite:
        suites = [s for s in suites if args.suite.lower() in s.lower()]
        if not suites:
            print(f"[ERROR] No suites match '{args.suite}'")
            print(f"Available: {', '.join(Path(s).stem for s in SUITES)}")
            sys.exit(1)

    total_passed = 0
    total_failed = 0
    all_failures: list[str] = []
    start_time = time.time()

    print(f"\npin0ccsAI Test Suite")
    print(f"{'='*50}")
    print(f"Running {len(suites)} suite(s)...\n")

    for suite_path in suites:
        if not Path(suite_path).exists():
            print(f"  SKIP  {suite_path} (file not found)")
            continue

        suite_start = time.time()
        passed, failed, failures = run_suite(suite_path, verbose=args.verbose)
        elapsed = time.time() - suite_start

        total_passed += passed
        total_failed += failed
        all_failures.extend(failures)

        suite_name = Path(suite_path).stem
        status = "✓" if failed == 0 else "✗"
        color_pass = passed
        color_fail = failed
        print(
            f"  {status}  {suite_name:35} "
            f"{passed:3} passed  {failed:3} failed  "
            f"({elapsed:.2f}s)"
        )

    elapsed_total = time.time() - start_time

    print(f"\n{'='*50}")
    print(f"  Total:  {total_passed} passed,  {total_failed} failed")
    print(f"  Time:   {elapsed_total:.2f}s")
    print(f"{'='*50}")

    if all_failures:
        print(f"\nFAILURES ({len(all_failures)}):")
        for msg in all_failures:
            print(msg)
        sys.exit(1)
    else:
        print("\n  All tests passed.")
        sys.exit(0)


if __name__ == "__main__":
    main()
