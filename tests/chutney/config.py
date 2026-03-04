from __future__ import annotations

import dataclasses
import json
import os

from pathlib import Path


@dataclasses.dataclass
class Config:
    chutney: str
    arti: str
    arti_bench: str
    chutney_data_dir: str
    network: str

    def export_env(self) -> None:
        os.environ["CHUTNEY_ARTI"] = self.arti
        os.environ["CHUTNEY_DATA_DIR"] = self.chutney_data_dir

    def dump_json(self, dst: Path) -> None:
        with dst.open("w") as c:
            json.dump(dataclasses.asdict(self), c, indent=2)

    @staticmethod
    def load_json(src: Path) -> Config:
        with src.open("r") as c:
            j = json.load(c)
        return Config(**j)
