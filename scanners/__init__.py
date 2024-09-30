import datetime
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

    def absolute_conf_path(self, path):
        """Handy shortcut to get an absolute path into a scanner's config parameter.
        WARNING: currently, `path` MUST be in string for (e.g.: `spiderAjax.parameters.maxCrawlDepth`)
        """
        return f"scanners.{self.ident}.{path}"

    def my_conf(self, path, *args, **kwargs):
        """Handy shortcut to get the scanner's configuration.
        Only for within `scanners.<scanner>`
        WARNING: currently, `path` MUST be in string for (e.g.: `spiderAjax.parameters.maxCrawlDepth`)
        """
        return self.config.get(self.absolute_conf_path(path), *args, **kwargs)

    def set_my_conf(self, path, *args, **kwargs):
        """Handy shortcut to set the scanner's configuration.
        Only for within `scanners.<scanner>`
        """
        return self.config.set(f"scanners.{self.ident}.{path}", *args, **kwargs)

    def postprocess(self):
        """Final check to verify nothing went wrong during the scan"""

        # Verify that we didn't get throttled by PID limits (for multithreaded scanners)
        try:
            with open("/sys/fs/cgroup/pids.events", encoding="utf-8") as f:
                for line in f.readlines():
                    event, value = line.rstrip().split(sep=" ")
                    if event == "max" and value != "0":
                        logging.warning(
                            "Scanner may have been throttled by CGroupv2 PID limits: "
                            f"pids.events reports {event} {value}"
                        )
                    elif event != "max":
                        logging.warning(f"unknown pids.events report: {event} {value}")
        except FileNotFoundError:
            logging.debug("No CGroupv2 pids.events (normal if in a root CGroup)")

    def _should_export_to_defect_dojo(self):
        """Return a truthful value if Defect Dojo export is configured and not disbaled
        Returns True if:
        - an global export is configured (config.googleCloudStorage or config.defectDojo)
        - this particular scanner's export is not explicitely disabled (`defectDojoExport` is not False)
        """
        return self.my_conf("defectDojoExport") is not False and (
            self.config.get("config.googleCloudStorage")
            or self.config.get("config.defectDojo")
        )

    def _fill_up_data_for_defect_dojo(self, data):
        """
        Parent / common code for extracting data for defectdojo.
        This code should be called by the scanner's data_for_defect_dojo()
        Assumptions:
        - data["scan_type"] is already set
        """
        # default values
        default = {
            "product_name": self.config.get_official_app_name(),
            "active": True,
            "verified": False,
        }
        for key, value in default.items():
            if key not in data:
                data[key] = value

        # lists of configured import parameters
        params_root = "defectDojoExport.parameters"
        import_params = self.my_conf(params_root, default={}).keys()

        # overload that list onto the defaults
        for param in import_params:
            data[param] = self.my_conf(f"{params_root}.{param}")

        if data.get("test") is not None:
            # A test ID is provided: it takes precedence.
            # This is a reimport
            # remove unnecessary data
            for e in ("product_name", "engagement_name", "engagement"):
                if e in data:
                    del data[e]
        elif data.get("engagement") is not None:
            # An engagement ID is provided
            # remove unnecessary data
            for e in ("product_name", "engagement_name"):
                if e in data:
                    del data[e]
        else:
            # Neither test of engagement IDs provided: make sure there is enough data for import
            # A default product name was chosen as part of `self.get_default_defectdojo_data()`
            # Generate an engagement name if none are set
            if not data.get("engagement_name"):
                data[
                    "engagement_name"
                ] = f"RapiDAST-{data['product_name']}-{datetime.date.today()}"

        return data

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
