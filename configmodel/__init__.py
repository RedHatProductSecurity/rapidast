import copy
import logging
import os
from pprint import pformat


class RapidastConfigModel:
    def __init__(self, conf=None):
        if conf is None:
            conf = {}

        self.conf = conf

    def get(self, path, default=None):
        """Retrieve a config value as the following:
        1) if config entry `path` entry exists, return its value
        2) if config entry f"{path}_from_var" exist,
           AND that the value corresponds to an existing environment variable
           THEN return the value of that environment variable
        3) return default

        path is either a list of values, or a dot-separated string
        """
        path = path_to_list(path)

        # 1) Try to return value from config
        try:
            return self._get_from_conf(path)
        except KeyError:
            pass

        # 2) Try to get a `..._from_var` entry, and, if so, return the variable value
        new_path = path.copy()
        new_path[-1] = new_path[-1] + "_from_var"
        try:
            env_name = self._get_from_conf(new_path)
            return os.environ[env_name]
        except KeyError:
            pass

        # 3) return default
        return default

    def _get_from_conf(self, path):
        """Walks `path` in the config, and returns the corresponding value
        - This method is meant to be private to the ConfigModel
        - If the path does not exist return an KeyError exception, which MUST be handled by the caller
        - `path` should already be translated to a list of value
        """

        walk = self.conf
        try:
            for e in path:
                walk = walk[e]
            return walk
        except TypeError:
            pass
        except KeyError:
            pass
        except AttributeError:
            pass
        # Failed to iterate until the end: the path does not exist
        logging.debug(f"Config path {path} was not found")
        raise KeyError(f"{path} did not exist in the config")

    def delete(self, path):
        """Delete path"""
        path = path_to_list(path)
        walk = self.conf
        try:
            for e in path[:-1]:
                walk = walk[e]
            del walk[path[-1]]
            return True
        except KeyError:
            pass
        except AttributeError:
            pass
        # Failed to iterate until the end: the path does not exist
        logging.warning(
            f"RapidastConfigModel.delete(): Config path {path} was not found. No deletion"
        )
        return False

    def exists(self, path):
        """Returns true if `path` exists in configuration
        Even if the value is None
        """
        path = path_to_list(path)
        tmp = self.conf
        try:
            for key in path:
                tmp = tmp[key]
            return True
        except TypeError:
            return False
        except KeyError:
            return False

    def set(self, path, value, overwrite=True):
        """Set the value pointed by `path` to `value`
        - Create the path if necessary
        - To prevent modification of existing value: overwrite=False
        - Discard previous value
        - Overwrite (with a warning) path if necessary (if something in the path was not a dict)
        - Returns True if a modifcation was made
        """
        path = path_to_list(path)
        walk = self.conf

        # Walk the path, create subdictionary if needed
        for key in path[:-1]:
            # case 1: path not fully created
            if key not in walk.keys():
                walk[key] = {}
                walk = walk[key]
                continue
            tmp = walk[key]
            # case 2: not a "dictionary" type: warn and overwrite (if True)
            if not isinstance(tmp, dict):
                logging.warning(
                    f"RapidastConfigModel.set: Incompatible {path} at {tmp}"
                )
                if not overwrite:
                    logging.info("RapidastConfigModel.set: no overwrite: early return")
                    return False
                walk[key] = {}
            walk = walk[key]
        if overwrite or not walk.get(path[-1]):
            walk[path[-1]] = value
            return True
        return False

    def move(self, orig, dest):
        """Move a subtree to another location. Nothing happens if the origin does not exist
        Both `orig` and `dest` are paths (list or dot-separated string) within the configuration
        """

        orig = path_to_list(orig)
        dest = path_to_list(dest)

        if dest[0 : len(orig)] == orig:
            raise ValueError("Moving config entry to a subentry is not supported")

        if self.exists(orig):
            self.set(dest, self.get(orig))
            self.delete(orig)
            logging.debug(f"Moved '{orig}' to '{dest}'")
        else:
            logging.debug(f"NOT moving '{orig}' as it did not exist")

    def merge(self, merge, preserve=False, root=None):
        """Recursively merge `merge` into the configuration.
        - if `preserve` is True, in case of value collision, keep previous
        - if `root`, then merge `merge` into `self.conf[root...]`
        """

        if not merge:
            return
        if not isinstance(merge, dict):
            raise TypeError(
                f"RapidastConfigModel.merge: merge must be a dict (was: {type(merge)})"
            )

        root = path_to_list(root)

        if root and not self.exists(root):
            self.set(root, {})

        # get to the root of the merging
        sub_conf = self.get(root)

        deep_dict_merge(sub_conf, merge, preserve)

    def __repr__(self):
        return pformat(vars(self), indent=4, width=1)


## BELOW: utility functions


def path_to_list(path):
    """Ensure that a path is a list
    - if it's a list, keep it as it is
    - if it's a string, split by '.'
    - Otherwise, just try to convert to list

    e.g.:
    - path_to_list('abc') => ['abc']
    - path_to_list('a.b.c') => ['a','b','c']
    - path_to_list(('a','b','c')) => ['a','b','c']
    """

    if not path:
        return []
    if isinstance(path, str):
        path = path.split(".")
    return list(path)


def deep_dict_merge(dest, merge, preserve=False):
    """Modifies and returns the 'dest' dict, after merging 'merge' into it

    Deep (recursively) merge the dict "merge" into "dest".
    Recursively means that if a key exist in both dicts, and they both point
    to a dict, the merge will recurse instead of overwriting.
    Think of it as a recursive `dest += merge`

    In case of key collision
    (a key exists in both dicts, but at most 1 is a dict):
    - if preserve is True: the value taken from `dest` is favored
    - if preserve is False: the value taken from `merge` is favored

    Notes/Warnings/Limitations:
    - `dest` is modified during the process
    - it can't be used to remove an entry, even with preserve=False
    - the copy is done using deepcopy() to prevent accidental cross-modification

    Example:
    deep_dict_merge({'key1':'val1', 'key2':'val2'}, {'key2':'newVal'}, False)
     - Will modify the first argument to {'key1':'val1', 'key2':'newVal'}
     - And return it

    Internal :
     - for each key of `merge`:
        - if no correspondance in `dest`: value is imported
        - if both are dicts: descend in both recursively
        - else: copy or preserve, according to `preserve`
    """

    if merge is None:
        return dest

    if not isinstance(dest, dict) or not isinstance(merge, dict):
        logging.warning(
            "[deep_dict_merge]: one of the argument was NOT a dictionary. "
            "The function was likely called incorrectly and may result in incorrect behavior"
        )

    for key, val in merge.items():
        if not dest.get(key):
            dest[key] = copy.deepcopy(val)
        elif isinstance(dest[key], dict) and isinstance(val, dict):
            deep_dict_merge(dest[key], val, preserve)
        elif not preserve:
            dest[key] = copy.deepcopy(val)
    return dest
