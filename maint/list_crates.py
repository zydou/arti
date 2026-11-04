#!/usr/bin/env python3
#
# List our crates as they appear in Cargo.toml.

from __future__ import annotations

import argparse
import toml.decoder

from typing import Iterator, Any
from dataclasses import dataclass
from pathlib import Path

TOPDIR = Path(__file__).absolute().parent.parent
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


def list_crates() -> Iterator[Crate]:
    """
    Iterator over all the crates in the workspace.
    """
    t = toml.decoder.load(WORKSPACE_TOML)
    for subdir in t["workspace"]["members"]:
        yield Crate.from_subdir(Path(subdir))


def print_crates(args: argparse.Namespace) -> None:
    shown_any = False
    for c in list_crates():
        show = (
            args.package == c.name
            if args.package is not None
            else args.all or c.publish
        )
        if not show:
            continue
        shown_any = True
        if args.version:
            print("%-23s %s" % (c.name, c.version))
        elif args.subdir:
            print(c.subdir)
        else:
            print(c.name)

    assert shown_any


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="list-crates",
        description="list crates (by default, only the ones to publish)",
    )
    parser.add_argument(
        "--all", action="store_true", help="list even unpublished crates"
    )
    parser.add_argument("--version", action="store_true", help="print versions")
    parser.add_argument(
        "--subdir", action="store_true", help="print relative directories"
    )
    parser.add_argument("-p", "--package", help="specific crate")

    args = parser.parse_args()
    print_crates(args)
