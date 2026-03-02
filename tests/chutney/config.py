from __future__ import annotations

import dataclasses

from pathlib import Path

@dataclasses.dataclass
class Config:
    chutney: str
    arti: str
    arti_bench: str
    jq: str
    chutney_data_dir: str
    network: str

