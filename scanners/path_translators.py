# This module provides a helper for keeping track of path translations between the "container" view and the "host" view
from collections import namedtuple
from pathlib import PosixPath
from pathlib import PurePosixPath

PathMap = namedtuple("PathMap", ["host", "container"])


class PathMaps:
    def __init__(self):
        self.paths = {}  # ID => ("host", "container")

    def add(self, id_, host, container):
        self.paths[id_] = PathMap(host, container)

    def get(self, id_):
        return self.paths[id_]

    def list_container_paths(self):
        return [x.container for x in self.paths]

    def list_host_paths(self):
        return [x.host for x in self.paths]

    def list_ids(self):
        return self.paths.keys()

    def host_2_container(self, path):
        """Given a path on the host, find out what will be its path in the container, based on mapping
        WARNING: no support for subvolumes. we would need to find the "best match"
        """
        path = PosixPath(path).resolve()
        for mapping in self.paths.values():
            # force resolution to make sure we work with absolute paths
            host = PosixPath(mapping.host).resolve()

            # PurePath.is_relative_to() was added in python 3.9, so we have to use `parents` for now
            if host == path or host in path.parents:
                # match! replace the host path by the container path
                path = PurePosixPath(mapping.container, path.relative_to(host))
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
        for mapping in self.paths.values():
            container = PurePosixPath(mapping.container)

            # PurePath.is_relative_to() was added in python 3.9 only, so we have to use `parents` for now
            if container == path or container in path.parents:
                # match! replace the container path by the host path
                path = PosixPath(mapping.host, path.relative_to(container))
                return str(path)

        raise RuntimeError(
            f"container_2_host(): unable to find a container path for path {path}",
            f"container map list: {self.list_container_paths()}",
        )
