# This module provides a helper for keeping track of path translations between the "container" view and the "host" view
from collections import namedtuple
from pathlib import PosixPath
from pathlib import PurePosixPath

PathMap = namedtuple("PathMap", ["host_path", "container_path"])


def make_mapping_for_scanner(name, *kargs):
    """Given a Scanner name and a list of (ID, host_path, container_path) tuples: prepare an object.
    The object has "host" and "container" which can be access via <obj>.<ID> as attributes

    myobj = make_mapping_for_scanner("Zap", ("work", "/tmp/rapidast", "/zap"))

    myobj.work.host_path  # returns "/tmp/rapidast"
    myobj.container_2_host("/zap/my/file") # returns "/tmp/rapidast/my/file
    """

    ids = [x[0] for x in kargs]
    _mapping = namedtuple(f"{name}PathMaps", ids)

    def host_2_container(self, path):
        """Given a path on the host, find out what will be its path in the container, based on mapping
        WARNING: no support for subvolumes. we would need to find the "best match"
        """
        path = PosixPath(path).resolve()
        for mapping in self:
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
        for mapping in self:
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

    def list_container_paths(self):
        return [x.container_path for x in self]

    def list_host_paths(self):
        return [x.host_path for x in self]

    def list_ids(self):
        return self.keys()

    _mapping.host_2_container = host_2_container
    _mapping.container_2_host = container_2_host
    _mapping.list_ids = list_ids
    _mapping.list_host_paths = list_host_paths
    _mapping.list_container_paths = list_container_paths
    _mapping.list_container_paths = list_container_paths

    tuples = (PathMap(host_path=x[1], container_path=x[2]) for x in kargs)

    mymapping = _mapping(*tuples)

    return mymapping
