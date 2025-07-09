from dataclasses import dataclass
from typing import Optional

from configmodel.models.application import Application
from configmodel.models.config import Config
from configmodel.models.general import General


@dataclass
class Root:
    config: Config
    application: Application
    general: Optional[General] = None


# @TODO: We could add scanner configurations here as well.
# However, this would require additional logic to dynamically validate dataclasses
# based on scanner key names, which would complicate the validation process.
# The current approach is simpler, as each scanner validates its own configuration internally upon loading.
# scanners:
