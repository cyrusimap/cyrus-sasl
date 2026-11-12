#!/usr/bin/env python3
"""Run the Cyrus SASL wire-level conformance tests.

Usage: run.py [-v] [-k PATTERN] [--report]

Environment:
  T_BUILDDIR   directory holding the built t_srv and t_cli drivers
               (default: the tests/ directory next to this file)
  T_PLUGINDIR  directory holding the built plugins (plugins/.libs)

Exit status is non-zero if any test fails, errors, or unexpectedly passes.
An unexpected pass means a known bug was fixed: remove its @known_bug
marker so the test guards against regressions.
"""

import argparse
import collections
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)


def test_method(test):
    return getattr(test, test._testMethodName, None)


class ConformanceResult(unittest.TextTestResult):
    def __init__(self, *args, **kw):
        super().__init__(*args, **kw)
        self.outcomes = []  # (test, outcome)

    def _record(self, test, outcome):
        self.outcomes.append((test, outcome))

    def addSuccess(self, test):
        super().addSuccess(test)
        self._record(test, "pass")

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self._record(test, "FAIL")

    def addError(self, test, err):
        super().addError(test, err)
        self._record(test, "ERROR")

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        self._record(test, "skip")

    def addExpectedFailure(self, test, err):
        super().addExpectedFailure(test, err)
        self._record(test, "known bug")

    def addUnexpectedSuccess(self, test):
        super().addUnexpectedSuccess(test)
        self._record(test, "FIXED?")


def print_report(result, stream):
    known = []
    fixed = []
    by_spec = collections.OrderedDict()

    for test, outcome in result.outcomes:
        method = test_method(test)
        bug = getattr(method, "known_bug", None)
        if bug and outcome == "known bug":
            known.append((bug, test))
        elif bug and outcome == "FIXED?":
            fixed.append((bug, test))
        for ref, section, level, _ in getattr(method, "spec_tags", []):
            counts = by_spec.setdefault(ref, collections.Counter())
            counts[outcome] += 1

    w = stream.write
    w("\n=== Conformance summary by spec ===\n")
    cols = ["pass", "known bug", "FAIL", "ERROR", "FIXED?", "skip"]
    w("%-10s" % "spec" + "".join("%11s" % c for c in cols) + "\n")
    for ref in sorted(by_spec):
        counts = by_spec[ref]
        w("%-10s" % ref + "".join("%11d" % counts[c] for c in cols) + "\n")

    if known:
        w("\n=== Known bugs still present (expected failures) ===\n")
        for (audit_id, summary), test in sorted(known, key=lambda x: (x[0][0], x[1].id())):
            w("  %-5s %s\n        %s\n" % (audit_id, summary, test.id()))

    if fixed:
        w("\n=== Known bugs that now PASS: remove their @known_bug markers ===\n")
        for (audit_id, summary), test in fixed:
            w("  %-5s %s\n        %s\n" % (audit_id, summary, test.id()))


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("-k", dest="pattern", action="append",
                        help="only run tests whose name contains PATTERN")
    args = parser.parse_args()

    loader = unittest.TestLoader()
    if args.pattern:
        loader.testNamePatterns = ["*%s*" % p for p in args.pattern]
    suite = loader.discover(HERE, pattern="test_*.py", top_level_dir=HERE)

    import sasltest
    print("Sanitizers: %s" % ("on (memory and undefined-behavior errors fail tests)"
                              if sasltest.SANITIZED else "off"))
    sys.stdout.flush()

    runner = unittest.TextTestRunner(verbosity=2 if args.verbose else 1,
                                     resultclass=ConformanceResult,
                                     stream=sys.stdout)
    result = runner.run(suite)
    print_report(result, sys.stdout)
    sys.stdout.flush()
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
