from __future__ import annotations

import dataclasses
import json
import os

from pathlib import Path
from typing import Optional


@dataclasses.dataclass
class Config:
    """Test configuration

    Generated and written out by the `setup` script,
    and read by other test scripts."""

    # path to the chutney CLI executable
    chutney: str
    # path to the arti client executable
    arti: str
    # path to the arti-extra client executable
    arti_extra: str
    # path to the arti-bench executable
    arti_bench: str
    # chutney data directory (CHUTNEY_DATA_DIR)
    chutney_data_dir: str
    # chutney CLI-flag network specification (e.g. "--net=basic-min")
    network: Optional[str]

    def export_env(self) -> None:
        """Set environment variables based on this config"""
        os.environ["CHUTNEY_ARTI"] = self.arti
        os.environ["CHUTNEY_DATA_DIR"] = self.chutney_data_dir

    def dump_json(self, dst: Path) -> None:
        """Dump this config as json to `dst`"""
        with dst.open("w") as c:
            json.dump(dataclasses.asdict(self), c, indent=2)

    @staticmethod
    def load_json(src: Path) -> Config:
        """Load a config previously written via `dump_json` from `src`"""
        with src.open("r") as c:
            j = json.load(c)
        return Config(**j)
