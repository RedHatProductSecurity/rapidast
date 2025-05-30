from dataclasses import dataclass
from dataclasses import field
from typing import Any
from typing import Dict


@dataclass
class GarakConfig:
    parameters: Dict[str, Any] = field(default_factory=dict)
    # The path to the Garak executable
    executable_path: str = field(default="/usr/local/bin/garak")
