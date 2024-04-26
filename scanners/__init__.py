import importlib
import logging
import os
import shutil
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

        # When requested to create a temporary file or directory, it will be a subdir of
        # this temporary directory
        self.main_temp_dir = None

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
        """
        This function creates a temporary directory aiming at storing data used by the scanner
        Then create subdirectories based on the name given, under that temporary
        Return the full path to that location.

        Example:
        -> on first call, `zap._create_temp_dir(name="home")`
           will create /tmp/rapidast_zap_RanD0m/home/
        -> on second call, `zap._create_temp_dir(name="work")`
           will create /tmp/rapidast_zap_RanD0m/work/

        The /tmp/rapidast_zap_RanD0m/ directory will be removed in cleanup()
        """
        # first call: create a temporary dir
        if not self.main_temp_dir:
            self.main_temp_dir = tempfile.mkdtemp(prefix=f"rapidast_{self.ident}_")
            logging.debug(f"Temporary directory created in host: {self.main_temp_dir}")

        temp_dir = os.path.join(self.main_temp_dir, name)
        os.mkdir(temp_dir)
        return temp_dir

    def cleanup(self):
        """Generic Scanner cleanup: should be called only via super() inheritance
        Deletes the _create_temp_dir() parent directory
        """
        if self.main_temp_dir:
            logging.debug(f"Deleting temp directories {self.main_temp_dir}")
            shutil.rmtree(self.main_temp_dir)
        else:
            logging.debug("No temporary file to cleanup")


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
