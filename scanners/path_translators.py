# This module provides a helper for keeping track of path translations between the "container" view and the "host" view
from collections import namedtuple
from pathlib import PosixPath
from pathlib import PurePosixPath

# This associates 2 paths together
PathMap = namedtuple("PathMap", ["host_path", "container_path"])


# A decorator that let object's _data dictionary be accessed by the key directly, as if it were attributes.
def dynamic_attributes(cls):
    class Wrapper(cls):
        def __getattr__(self, key):
            if key in self._data:
                return self._data[key]
            raise AttributeError(
                f"{self.__class__.__name__} object has no attribute '{key}'"
            )

        def __setattr__(self, key, value):
            if key == "_data":
                self.__dict__[key] = value
            elif key in self._data and self._data[key] is None:
                self._data[key] = value
            else:
                # Currently: do not allow new entries beyond what was set at creation time
                raise AttributeError(
                    f"{self.__class__.__name__} object has no attribute '{key}' or '{key}' was already set"
                )

    return Wrapper


@dynamic_attributes
class PathMaps:
    def __init__(self, *args):
        self._data = {id: None for id in args}

    def list_maps(self):
        """Return the list of namedtuples"""
        return self._data.values()

    def list_container_paths(self):
        """Return the list of all container paths"""
        return [m.container_path for m in self._data.values()]

    def list_host_paths(self):
        """Return the list of all host paths"""
        return [m.host_path for m in self._data.values()]

    def list_ids(self):
        """Return the list of all IDs (list of attributes)"""
        return self._data.keys()

    def host_2_container(self, path):
        """Given a path on the host, find out what will be its path in the container, based on mapping
        WARNING: no support for subvolumes. we would need to find the "best match"
        """
        path = PosixPath(path).resolve()
        for mapping in self._data.values():
            # force resolution to make sure we work with absolute paths
            host = PosixPath(mapping.host_path).resolve()

            # PurePath.is_relative_to() was added in python 3.9, so we have to use `parents` for now
            if host == path or host in path.parents:
                # match! replace the host path by the container path
                path = PurePosixPath(mapping.container_path, path.relative_to(host))
                return str(path)

        raise RuntimeError(
            f"host_2_container(): unable to find a host path for path {path}",
            f"host path list: {self.list_host_paths()}",
        )

    def container_2_host(self, path):
        """Given a path on the container, find out what will be its path in the host, based on mapping
        WARNING: no support for subvolumes. we would need to find the "best match"
        """
        path = PurePosixPath(path)
        for mapping in self._data.values():
            container = PurePosixPath(mapping.container_path)

            # PurePath.is_relative_to() was added in python 3.9 only, so we have to use `parents` for now
            if container == path or container in path.parents:
                # match! replace the container path by the host path
                path = PosixPath(mapping.host_path, path.relative_to(container))
                return str(path)

        raise RuntimeError(
            f"container_2_host(): unable to find a container path for path {path}",
            f"container map list: {self.list_container_paths()}",
        )
