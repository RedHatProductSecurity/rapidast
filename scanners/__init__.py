import importlib
from enum import Enum

import configmodel


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

    def __repr__(self):
        from pprint import pformat

        return pformat(vars(self), indent=4, width=1)


# Given a string representing a scanner, return the corresponding scanner class.
def str_to_scanner(name, type):
    mod = importlib.import_module(f"scanners.{name}.{name}_{type}")
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

        def decorator(zap_scanner):
            authenticator = zap_scanner.config.get(
                f"scanners.{scanner_name}.authentication.type", default=None
            )
            func = registry.get(authenticator, registry["error"])
            return func(zap_scanner)

        def dispatch(zap_scanner):
            return registry.get(zap_scanner, registry["error"])

        decorator.register = register
        decorator.registry = registry
        decorator.dispatch = dispatch

        return decorator

    return config_authentication_dispatcher
