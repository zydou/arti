from __future__ import annotations

import dataclasses

from pathlib import Path

@dataclasses.dataclass
class Config:
    chutney: Path
    arti: Path
    arti_bench: Path
    jq: Path
    chutney_data_dir: Path
    network: str

