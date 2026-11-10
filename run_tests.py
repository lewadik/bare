#!/usr/bin/env python3
"""Run the Haven test suite with the standard library only.

    python run_tests.py            # all tests
    python run_tests.py -v         # verbose
    python run_tests.py test_e2e   # one module (prefix match)

Works on a bare interpreter with ``-E -P`` (no PYTHONPATH, cwd not on
``sys.path``), which is how hardened launchers start Python.
"""

from __future__ import annotations

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.abspath(__file__))


def _summarize_failures(result: unittest.result.TestResult) -> None:
    """Mirror failures into $GITHUB_STEP_SUMMARY when running on Actions.

    Keeps the workflow run page useful: every error/failure traceback is
    visible without downloading logs.
    """
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    problems = [("error", item) for item in result.errors]
    problems += [("failure", item) for item in result.failures]
    if not problems:
        return
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(f"## Test problems ({len(problems)})\n\n")
        for kind, (test, tb) in problems[:20]:
            handle.write(
                f"<details><summary>{kind}: {test}</summary>\n\n"
                f"```\n{tb[:4000]}\n```\n</details>\n"
            )
        hidden = len(problems) - 20
        if hidden > 0:
            handle.write(f"\n({hidden} more problems not shown)\n")


def main(argv: list[str]) -> int:
    if ROOT not in sys.path:
        sys.path.insert(0, ROOT)
    verbose = "-v" in argv or "--verbose" in argv
    names = [item for item in argv[1:] if not item.startswith("-")]
    pattern = f"{names[0]}*.py" if names else "test_*.py"
    loader = unittest.TestLoader()
    suite = loader.discover(os.path.join(ROOT, "tests"), pattern=pattern, top_level_dir=ROOT)
    if loader.errors:
        for error in loader.errors:
            print(error, file=sys.stderr)
        return 1
    result = unittest.TextTestRunner(verbosity=2 if verbose else 1, buffer=False).run(suite)
    if not result.wasSuccessful():
        _summarize_failures(result)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
