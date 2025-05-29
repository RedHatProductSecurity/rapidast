# pylint: disable=invalid-name
from dataclasses import dataclass
from dataclasses import field
from typing import List
from typing import Optional

from ..general import ContainerType


@dataclass
class GenericContainerParameters:
    image: Optional[str] = None
    command: Optional[str] = None
    validReturns: Optional[str] = None
    podName: Optional[str] = None
    volumes: Optional[List[str]] = field(default_factory=list)


@dataclass
class GenericContainer:
    type: ContainerType = ContainerType.PODMAN
    parameters: Optional[GenericContainerParameters] = None


@dataclass
class GenericConfig:
    inline: Optional[str] = None
    results: Optional[str] = None
    toolDir: Optional[str] = None
    container: Optional[GenericContainer] = None
