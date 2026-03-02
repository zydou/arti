from __future__ import annotations

import dataclasses
import json

from pathlib import Path


@dataclasses.dataclass
class Config:
    chutney: str
    arti: str
    arti_bench: str
    jq: str
    chutney_data_dir: str
    network: str

    def dump_json(self, dst: Path) -> None:
        with dst.open("w") as c:
            json.dump(dataclasses.asdict(self), c, indent=2)
