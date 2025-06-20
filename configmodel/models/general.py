from enum import Enum


class ContainerType(str, Enum):
    PODMAN = "podman"
    NONE = "none"
