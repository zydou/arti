"""
Find tests, identify the ones that the user wants, and invoke them.
"""

from __future__ import annotations

import importlib
import traceback
from types import ModuleType
from typing import Generator

from arti_rpc_tests import FatalException
from arti_rpc_tests.context import TestContext

# Is this the right way to do this?
#
# Should we be instead listing all the files in $(basename __file__)/tests ?
_TEST_MODS = [
    "basic",
]


# Return a list of all the python modules that we should search for tests.
def all_modules() -> list[ModuleType]:
    return [
        importlib.import_module(f"arti_rpc_tests.tests.{name}") for name in _TEST_MODS
    ]


def run_tests(
    testfilter: TestFilter, modules: list[ModuleType], context: TestContext
) -> bool:
    """
    Run every test listed by `testfilter` in the provided `modules`,
    using the facilities in `context`.

    Return True if every test passed, and False otherwise.

    May raise FatalException if a test failed completely.
    """
    to_run: list[TestCase] = []

    for m in modules:
        to_run.extend(testfilter.list_tests(m))

    print(f"Found {len(to_run)} tests")

    successes = failures = 0
    for test in to_run:
        if test.run(context):
            successes += 1
        else:
            failures += 1

    if failures:
        print(f"{failures}/{len(to_run)} tests failed!")
    else:
        print(f"All {successes} tests succeeded")
    assert successes + failures == len(to_run)

    return failures == 0


class TestFilter:
    """
    Selects one or more tests that we should run.
    """

    def __init__(self):
        # No features supported yet
        pass

    def list_tests(self, module: ModuleType) -> Generator[TestCase]:
        """
        Yield every test in `module` that this filter permits.
        """
        for name in sorted(dir(module)):
            obj = getattr(module, name)

            if callable(obj) and getattr(obj, "arti_rpc_test", False):
                sname = name.removeprefix("test_")
                yield TestCase(f"{module.__name__}.{sname}", obj)


class TestCase:
    """
    A single test case.
    """

    def __init__(self, name, function):
        self.name = name
        self.function = function

    def run(self, context: TestContext) -> bool:
        """
        Try to run this test within `context`.

        Returns True on success and False on failure.

        May raise FatalEception if test execution should stop entirely.
        """
        try:
            print(self.name, "...", flush=True, end="")
            self.run_inner(context)
            print("OK")
            return True
        except FatalException:
            print("FATAL EXCEPTION")
            raise
        except Exception as ex:
            print("FAILED")
            traceback.print_exc()
            return False

    def run_inner(self, context: TestContext) -> None:
        """
        Run this test; raise an exception on failure.

        Raise a FatalException if all test execution should stop entirely.
        """
        if not context.arti_process.is_running():
            raise FatalException("Arti process not running at start of test!")

        self.function(context)

        if not context.arti_process.is_running():
            raise FatalException("Arti process not running at end of test!")
