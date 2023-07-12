import importlib
import logging
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

    def my_conf(self, path, default=None):
        """Handy shortcut to get the scanner's configuration.
        Only for within `scanners.<scanner>`
        """
        return self.config.get(f"scanners.{self.ident}.{path}", default)

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


###########################################################
# AUTHENTICATION HELPERS                                  #
# - authentication factory                                #
###########################################################


def generic_authentication_factory(scanner_name):
    """Decorator factory for generic authentication.
    First create the decorator:
        @generic_authentication_factory("zap")
        def authentication_factory(self):
            [ default action. i.e.: probably raise error]

    Then populate it by registering methods:
        @authentication_factory.register(None)
        def authentication_set_anonymous(self):
            [return authentication of type `None`]
    """

    def config_authentication_dispatcher(func):
        """This is intended to be a decorator to register authentication functions
        The function passed during creation will be called in case no suitable functions are found.
        i.e.: it should raise an error.

        It is possible to retrieve an authenticator by calling <dispatcher>.dispatch(<version>)
        This may be used for testing purpose
        """
        registry = {}  # "method" -> authenticator()

        registry["error"] = func

        def register(method):
            def inner(func):
                registry[method] = func
                return func

            return inner

        def decorator(scanner):
            authenticator = scanner.config.get(
                f"scanners.{scanner_name}.authentication.type", default=None
            )
            func = registry.get(authenticator, registry["error"])
            return func(scanner)

        def dispatch(scanner):
            return registry.get(scanner, registry["error"])

        decorator.register = register
        decorator.registry = registry
        decorator.dispatch = dispatch

        return decorator

    return config_authentication_dispatcher
