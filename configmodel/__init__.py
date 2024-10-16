import copy
import logging
import os
from pprint import pformat
import yaml
from rapidast import load_config_file


class RapidastConfigModel:
    def __init__(self, conf=None):
        if conf is None:
            conf = {}

        self.conf = conf
        self._default_conf = {}
        self._env_conf = {}

    def get(self, path, default=None):
        """Retrieve a config value as the following:
        1) if config entry `path` entry exists, return its value
        2) if config entry f"{path}_from_var" exist,
           AND that the value corresponds to an existing environment variable
           THEN return the value of that environment variable
        3) return default

        path is either a list of values, or a dot-separated string
        """

        def create_nested_dict(keys, value):
            nested_dict = value
            for key in reversed(keys):
                nested_dict = {key: nested_dict}
            return nested_dict

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
            env_value = os.environ[env_name]
            self._env_conf |= create_nested_dict(path, env_value)
            return env_value
        except KeyError:
            pass

        self._default_conf |= create_nested_dict(path, default)

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
        logging.warning(f"RapidastConfigModel.delete(): Config path {path} was not found. No deletion")
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
            # case 2: the value is None (path partially exists): initialize a dictionary
            if tmp is None:
                walk[key] = {}
                tmp = walk[key]
            # case 3: not a "dictionary" type: warn and overwrite (if True)
            if not isinstance(tmp, dict):
                logging.warning(f"RapidastConfigModel.set: Incompatible {path} at {tmp}")
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
            raise TypeError(f"RapidastConfigModel.merge: merge must be a dict (was: {type(merge)})")

        root = path_to_list(root)

        if root and not self.exists(root):
            self.set(root, {})

        # get to the root of the merging
        sub_conf = self.get(root)

        deep_dict_merge(sub_conf, merge, preserve)

    def subtree_to_dict(self, path):
        """Given a path, returns its subtree as a dictionary.
        This includes applying all the `*_from_var` transformation.
        e.g.:
        "{'a_from_var': 'A_VAR'}" would return "{'a': '<value of $A_VAR>'}"

        Cases:
        1- path does not exist: return None
        2- path does not point to a dictionary: throw a KeyError instance
        3- path exist and is a dictionary: copy it, walk the copy apply all _from_var, return the copy
        """

        # recursively descend the tree, and apply all the _from_var
        def descend(root):
            if isinstance(root, dict):
                # Dictionary:
                #  create a new dictionary, and apply the following logic:
                #  if key matches `_from_var`, assume value is a string, and apply replacement
                #  otherwise, copy key name and recursively descend on the value
                new = {}
                for key, val in root.items():
                    if key.endswith("_from_var"):
                        new[key.removesuffix("_from_var")] = os.environ[val]
                        if not new[key.removesuffix("_from_var")]:
                            logging.warning(f"configuration {key} points to environment variable {val}, which is empty")
                    else:
                        new[key] = descend(val)
                return new
            elif isinstance(root, list):
                # List: apply on each entry, and return a new List
                return [descend(val) for val in root]
            else:
                # root is just a value (integer, string), assuming it's immutable
                return root

        try:
            subtree = self._get_from_conf(path_to_list(path))
        except KeyError:
            logging.debug(f"subtree_to_dict(): path '{path}' does not exist")
            return None

        if not isinstance(subtree, dict):
            raise KeyError(f"subtree_to_dict(): '{path}' does not point to a dictionary in the config")

        return descend(subtree)

    def get_official_app_name(self):
        """Shortcut:
        Return a string corresponding to how the application should be called
        Based on the configuratoin.
        Prefer the full product name, but defer to short name if unavailable
        """
        return self.get("application.ProductName") or self.get("application.shortName")

    def __repr__(self):
        return pformat(vars(self), indent=4, width=1)

    @staticmethod
    def _dump_config(filename: str, config: dict) -> None:
        """
        Dumps the given configuration dictionary into a YAML file.

        Args:
            filename: The full path of the file where the configuration should be saved.
            config: The configuration dictionary to be written to the file.
        """
        try:
            with open(filename, "w+", encoding="utf-8") as f:
                yaml.dump(config, f, allow_unicode=True)
        except OSError as e:
            logging.error(f"Error writing to file {filename}: {e}")
        except yaml.YAMLError as e:
            logging.error(f"Error dumping YAML configuration: {e}")

    def dump(self, dirname: str) -> None:
        """
        Dumps both the main configuration and the default configuration into YAML files
        in the specified directory.

        Args:
            dirname: The directory path where the YAML files should be saved.
        """
        os.makedirs(dirname, exist_ok=True)

        render_config_file = os.path.join(dirname, "rendered-configuration.yaml")
        self._dump_config(render_config_file, self.conf)

        default_config_file = os.path.join(dirname, "default-configuration.yaml")
        self._dump_config(default_config_file, self._default_conf)

        env_config_file = os.path.join(dirname, "env-configuration.yaml")
        self._dump_config(env_config_file, self._env_conf)


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
