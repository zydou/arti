#!/usr/bin/env python3
#
# List our crates as they appear in Cargo.toml.

from __future__ import annotations

import argparse
import functools
import re
import subprocess
import sys
import toml.decoder

from typing import Iterator, Any, Optional
from dataclasses import dataclass
from pathlib import Path

TOPDIR = Path(__file__).resolve().parent.parent
WORKSPACE_TOML = TOPDIR.joinpath("Cargo.toml")


@dataclass
class Crate:
    """Information about one crate"""

    name: str
    subdir: str
    publish: bool
    version: str
    raw_metadata: Any

    @staticmethod
    def from_raw_cargo_contents(subdir: Path, contents: str) -> Crate:
        pt = toml.decoder.loads(contents)
        package = pt["package"]["name"]
        publish = pt["package"].get("publish")
        version = pt["package"]["version"]
        if publish is None:
            publish = True
        return Crate(package, str(subdir), publish, version, pt)

    @staticmethod
    def from_subdir(subdir: Path) -> Crate:
        contents = TOPDIR.joinpath(subdir, "Cargo.toml").read_text()
        return Crate.from_raw_cargo_contents(subdir, contents)

    def at_revision(self, git_rev: str) -> Optional[Crate]:
        """Return this crate's metadata at `git_rev`, if it existed then"""

        # git show doesn't seem to like absolute paths. We'll set cwd to TOPDIR,
        # and use a relative path.
        toml_path = Path(self.subdir, "Cargo.toml")
        try:
            cargo_at_rev = subprocess.check_output(
                ["git", "show", f"{git_rev}:{str(toml_path)}"],
                text=True,
                cwd=TOPDIR,
                stderr=subprocess.DEVNULL,
            )
        except subprocess.CalledProcessError:
            # Presume that it didn't exist.
            # Caller should have already ensured the `git_rev` is a valid revision.
            return None
        return Crate.from_raw_cargo_contents(Path(self.subdir), cargo_at_rev)

    def dir(self) -> Path:
        return TOPDIR.joinpath(self.subdir)

    def is_changed_since(self, git_rev: str, base_git_rev: str = "HEAD") -> bool:
        res = subprocess.run(
            [
                "git",
                "diff",
                "--quiet",
                "--exit-code",
                f"{git_rev}..{base_git_rev}",
                self.subdir,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=TOPDIR,
        )
        match res.returncode:
            case 0:
                return False
            case 1:
                return True
            case _:
                raise Exception(f"git diff failed: {res}")

    def is_bumped_since(self, git_rev: str) -> bool:
        prev = self.at_revision(git_rev)
        if prev is None:
            # bumped from non-existence to initial
            return True
        return prev.version != self.version


def list_crates() -> Iterator[Crate]:
    """
    Iterator over all the crates in the workspace.
    """
    t = toml.decoder.load(WORKSPACE_TOML)
    for subdir in t["workspace"]["members"]:
        yield Crate.from_subdir(Path(subdir))


@functools.cache
def _rev_exists(git_rev: str) -> bool:
    try:
        subprocess.check_call(
            ["git", "rev-parse", git_rev],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            cwd=TOPDIR,
        )
    except subprocess.CalledProcessError:
        return False
    return True


def get_required_prev_rev(args: argparse.Namespace, dependent_arg: str) -> str:
    rev = args.prev_rev
    if rev is None:
        print(
            f"Error: PREV_REV must be set when using {dependent_arg}", file=sys.stderr
        )
        sys.exit(1)
    assert isinstance(rev, str)
    if not _rev_exists(rev):
        print(f"Error: PREV_REV={rev} appears to be invalid", file=sys.stderr)
        sys.exit(1)
    return rev


def print_crates(args: argparse.Namespace) -> None:
    package_regex = None
    if args.only_matching_regex is not None:
        try:
            package_regex = re.compile(args.only_matching_regex)
        except re.PatternError as e:
            print(f"--only-matching-regex had bad regex: {e}")
            sys.exit(1)
    for c in list_crates():
        if package_regex is not None:
            if not package_regex.match(c.name):
                continue
        if args.package is not None and args.package != c.name:
            continue
        if not args.all and not c.publish:
            continue
        if args.only_unstable is True and not c.version.startswith("0."):
            continue
        if args.only_changed is True:
            prev_rev = get_required_prev_rev(args, "--only-changed")
            if not c.is_changed_since(prev_rev):
                continue
        if args.only_unchanged is True:
            prev_rev = get_required_prev_rev(args, "--only-unchanged")
            if c.is_changed_since(prev_rev):
                continue
        if args.only_unbumped is True:
            prev_rev = get_required_prev_rev(args, "--only-unbumped")
            if c.is_bumped_since(prev_rev):
                continue
        if args.version:
            print("%-23s %s" % (c.name, c.version))
        elif args.subdir:
            print(c.subdir)
        else:
            print(c.name)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="list-crates",
        description="list crates (by default, only the ones to publish)",
    )
    parser.add_argument(
        "--all", action="store_true", help="list even unpublished crates"
    )
    parser.add_argument(
        "--prev-rev", help="set PREV_REV, which is required for some other arguments."
    )
    parser.add_argument(
        "--only-changed",
        action="store_true",
        help="only show crates changed since PREV_REV",
    )
    parser.add_argument(
        "--only-unchanged",
        action="store_true",
        help="only show crates that HAVEN'T changed since PREV_REV",
    )
    parser.add_argument(
        "--only-unbumped",
        action="store_true",
        help="only show crates whose version hasn't been bumped since PREV_REV",
    )
    parser.add_argument(
        "--only-unstable",
        action="store_true",
        help="only show crates whose version is 0.*",
    )
    parser.add_argument(
        "--only-matching-regex",
        help="only show crates whose name matches the given regex",
    )
    parser.add_argument("--version", action="store_true", help="print versions")
    parser.add_argument(
        "--subdir", action="store_true", help="print relative directories"
    )
    parser.add_argument("-p", "--package", help="specific crate")

    args = parser.parse_args()
    print_crates(args)
