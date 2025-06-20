from dataclasses import dataclass
from dataclasses import field
from typing import Any
from typing import Dict
from typing import List
from typing import Optional


@dataclass
class NessusAuthenticationConfig:
    type: str
    parameters: Dict[str, Any]


@dataclass
class NessusServerConfig:
    url: str
    username: str
    password: str


@dataclass
class NessusScanConfig:
    name: str
    policy: str
    targets: List[str]
    folder: str = field(default="rapidast")
    timeout: int = field(default=600)  # seconds

    def targets_as_str(self) -> str:
        return " ".join(self.targets)


@dataclass
class NessusConfig:
    authentication: Optional[NessusAuthenticationConfig]
    server: NessusServerConfig
    scan: NessusScanConfig
