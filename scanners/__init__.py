import importlib
from enum import Enum
from pprint import pformat

import configmodel
from .path_translators import PathMaps


class State(Enum):
    UNCONFIGURED = 0
    ERROR = 1
    READY = 2
    DONE = 3
    PROCESSED = 4
    CLEANEDUP = 5


class RapidastScanner:
    def __init__(self, config):
        self.config = config
        self.state = State.UNCONFIGURED

        self.path_map = PathMaps()

    def __repr__(self):
        return pformat(vars(self), indent=4, width=1)


# Given a string representing a scanner, return the corresponding scanner class.
# For example : str_to_scanner("zap", "podman") will load `scanners/zap/zap_podman.py`
def str_to_scanner(name, method):
    mod = importlib.import_module(f"scanners.{name}.{name}_{method}")
    class_ = getattr(mod, mod.className)
    return class_


# This is a decorator factory for generic authentication.
# Method:


def generic_authentication_factory(scanner_name):
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
