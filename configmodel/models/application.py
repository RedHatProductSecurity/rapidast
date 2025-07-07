# pylint: disable=C0103
from dataclasses import dataclass
from typing import Optional


@dataclass
class Application:
    url: Optional[str] = None
    shortName: str = "scannedApp"
