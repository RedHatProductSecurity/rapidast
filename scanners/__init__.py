import importlib
import logging
import os
import tempfile
from enum import Enum
from pprint import pformat

import configmodel


class State(Enum):
    UNCONFIGURED = 0
    ERROR = 1
    READY = 2
    DONE = 3
    PROCESSED = 4
    CLEANEDUP = 5


class RapidastScanner:
    def __init__(self, config, ident):
        self.ident = ident
        self.config = config
        self.state = State.UNCONFIGURED

        self.results_dir = os.path.join(
            self.config.get("config.results_dir", default="results"), self.ident
        )

    def my_conf(self, path, *args, **kwargs):
        """Handy shortcut to get the scanner's configuration.
        Only for within `scanners.<scanner>`
        """
        return self.config.get(f"scanners.{self.ident}.{path}", *args, **kwargs)

    def set_my_conf(self, path, *args, **kwargs):
        """Handy shortcut to set the scanner's configuration.
        Only for within `scanners.<scanner>`
        """
        return self.config.set(f"scanners.{self.ident}.{path}", *args, **kwargs)

    def __repr__(self):
        return pformat(vars(self), indent=4, width=1)

    def _create_temp_dir(self, name="X"):
        """This function simply creates a temporary directory aiming at storing data in transit.
        This directory must be manually deleted by the caller during cleanup.
        Descendent classes *may* overload this directory (e.g.: if they can't map /tmp)
        """
        temp_dir = tempfile.mkdtemp(prefix=f"rapidast_{self.ident}_{name}_")
        logging.debug(f"Temporary directory created in host: {temp_dir}")
        return temp_dir


def str_to_scanner(name, method):
    """Given a scanner ID (name) and a container method, returns the class to be loaded
    `name` is in the form "<scanner>[_<id>]", where:
      - <scanner> is the name of the scanner
      - <id> is an optional identifier, allowing multiple instances of the same scanner
        <id> simply needs to be discarded here
    e.g.:
    - "zap_unauth", "podman" : returns ZapPodman, loaded from `scanners/zap/zap_podman.py`
    - "zap", "none" : returns ZapNone loaded from `scanners/zap/zap_none.py`
    """

    name = name.split("_")[0]
    mod = importlib.import_module(f"scanners.{name}.{name}_{method}")
    class_ = getattr(mod, mod.CLASSNAME)
    return class_
