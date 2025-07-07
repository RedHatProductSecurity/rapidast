# pylint: disable=C0103
from dataclasses import dataclass


@dataclass
class Application:
    url: str
    shortName: str = "scannedApp"
