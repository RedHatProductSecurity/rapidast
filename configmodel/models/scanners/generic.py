# pylint: disable=invalid-name
import logging
from dataclasses import dataclass
from dataclasses import field
from typing import List
from typing import Optional

from ..general import ContainerType


@dataclass
class GenericContainerParameters:
    image: Optional[str] = None
    command: Optional[str] = None
    validReturns: Optional[List[int]] = None
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

    def __post_init__(self):
        has_inline = bool(self.inline)
        has_container_paramenters_image = False
        if self.container is not None and self.container.parameters is not None:
            has_container_paramenters_image = bool(self.container.parameters.image)

        # @TODO: Consider raising an exception here
        # However, to maintain backward compatibility, we currently log an error instead
        if not (has_inline or has_container_paramenters_image):
            logging.error(
                "Configuration error: Either 'inline' content or a 'container.image' "
                "must be specified in the Generic Scanner settings"
                "Both are currently missing or empty"
            )

        if has_inline and has_container_paramenters_image:
            raise ValueError(
                "Configuration error: Only one of 'inline' content or 'container.image' "
                "can be specified in the Beneric Scanner settings. "
                "Both are currently configured, which is not allowed."
            )
