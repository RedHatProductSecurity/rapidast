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
