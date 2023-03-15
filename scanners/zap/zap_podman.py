import logging
import os
import random
import shutil
import string
import subprocess
import tarfile
import tempfile
from pathlib import PosixPath
from pathlib import PurePosixPath

import yaml

import configmodel
from .zap import Zap
from scanners import RapidastScanner
from scanners import State

className = "ZapPodman"

import pprint

pp = pprint.PrettyPrinter(indent=4)


class ZapPodman(Zap):
    DEFAULT_IMAGE = "docker.io/owasp/zap2docker-stable:latest"

    # path from the container
    ROOT_CONTAINER_DIR = "/zap"
    SCRIPTS_CONTAINER_DIR = f"{ROOT_CONTAINER_DIR}/scripts"
    POLICIES_CONTAINER_DIR = f"/home/zap/.ZAP/policies/"
    RESULTS_CONTAINER_DIR = f"{ROOT_CONTAINER_DIR}/results"  # R/W & keep
    SESSION_CONTAINER_DIR = f"{RESULTS_CONTAINER_DIR}/session_data/session"
    AF_CONTAINER_PATH = f"{RESULTS_CONTAINER_DIR}/af.yaml"

    def __init__(self, config):
        """Initialize all vars based on the config.
        The code of the function only deals with the "podman" layer, the "ZAP" layer is handled by super()
        """

        logging.debug(f"Initializing podman-based ZAP scanner")
        super().__init__(config)

        # This will contain all the podman options
        self.podman_opts = []

        # Container name in the form 'rapidast_zap_<app-shortName>_<random-chars>
        self.container_name = "rapidast_zap_{}_{}".format(
            self.config.get("application.shortName"),
            "".join(random.choices(string.ascii_letters, k=6)),
        )

        # working dir: this will be mounted as the results dir in the container
        # We store generated data (AF conf & env files) there for safekeep, as part of evidence
        self.temp_dir = tempfile.mkdtemp(prefix="rapidast_zap_")
        self.temp_af = f"{self.temp_dir}/af.yaml"
        logging.debug(f"Temporary directory for ZAP scanner: {self.temp_dir}")

        # a "host_path" -> "container_path" dictionary
        self.volume_map = {}

    # Public methods. each should call super()

    def setup(self):
        """Prepares everything:
        - the command line to run
        - environment variables
        - files & directory

        The code of the function only deals with the "podman" layer, the "ZAP" layer is handled by super()
        """

        if self.state != State.UNCONFIGURED:
            raise RuntimeError(
                f"Podman setup encounter an unexpected state: {self.state}"
            )
            self.state = State.ERROR

        # MUST be done _before_ super().setup, because we need to prepare volume mapping
        self._setup_podman_cli()

        super().setup(executable="/zap/zap.sh")

        # Save the Automation config, which is prepared by super().setup()
        self._save_automation_file()

    def _save_automation_file(self):
        """Save the Automation dictionary as YAML in the container"""
        self._generate_file(yaml.dump(self.af), ZapPodman.AF_CONTAINER_PATH)
        logging.info(f"Saved Automation Framework in {ZapPodman.AF_CONTAINER_PATH}")

    def _setup_podman_cli(self):
        logging.info(
            f"Preparing a podman container for the zap image, called {self.container_name}"
        )

        self.podman_opts += ["--name", self.container_name]

        # UID/GID mapping, in case of older podman version
        self._setup_zap_podman_id_mapping_cli()

        # Volume mappings
        self._add_volume(self.temp_dir, ZapPodman.RESULTS_CONTAINER_DIR)
        self._add_volume(self.SCRIPTS_LOCATION_DIR, ZapPodman.SCRIPTS_CONTAINER_DIR)
        self._add_volume(self.POLICIES_LOCATION_DIR, ZapPodman.POLICIES_CONTAINER_DIR)

        if self.state != State.ERROR:
            self.state = State.READY

    def run(self):
        """If the state is READY, run the final podman run command.
        There is no need to call super() here.
        """
        logging.info(f"Running up the ZAP scanner in podman")
        if not self.state == State.READY:
            raise RuntimeError(f"[ZAP SCANNER]: ERROR, not ready to run")

        cli = ["podman", "run"]
        cli += self.podman_opts
        cli.append(
            self.config.get(
                "scanners.zap.container.image", default=ZapPodman.DEFAULT_IMAGE
            )
        )

        # Update scanner as a first command, then actually run ZAP
        # currently, this is done via a `sh -c` wrapper
        commands = "zap.sh -cmd -addonupdate; " + " ".join(self.zap_cli)
        cli += ["sh", "-c", commands]

        # DO STUFF
        logging.info(f"Running ZAP with the following command:\n{cli}")
        result = subprocess.run(cli)
        logging.debug(
            f"ZAP returned the following:\n=====\n{pp.pformat(result)}\n====="
        )

        # Zap's return codes : https://www.zaproxy.org/docs/desktop/addons/automation-framework/
        if result.returncode in [0, 2]:
            # 0: ZAP returned correctly. 2: ZAP returned warning
            logging.info(
                f"The ZAP process finished with no errors, and exited with code {result.returncode}"
            )
            self.state = State.DONE
        else:
            # 1: Zap hit an error, >125 : podman returned an error
            logging.warning(
                f"The ZAP process did not finish correctly, and exited with code {result.returncode}"
            )
            self.state = State.ERROR

    def postprocess(self):
        logging.info(f"Running postprocess for the ZAP Podman environment")
        if not self.state == State.DONE:
            raise RuntimeError(
                f"No post-processing as ZAP has not successfully run yet."
            )

        super().postprocess()

        if not self.state == State.ERROR:
            self.state = State.PROCESSED

    def cleanup(self):
        logging.info(f"Running cleanup for the ZAP Podman environment")

        if not self.state == State.PROCESSED:
            raise RuntimeError(f"No cleanning up as ZAP did not processed results.")

        logging.debug(f"Deleting temp directory {self.temp_dir}")
        shutil.rmtree(self.temp_dir)

        logging.debug(f"Deleting podman container {self.container_name}")
        result = subprocess.run(["podman", "container", "rm", self.container_name])
        if result.returncode:
            logging.warning(f"Failed to delete container {self.container_name}")
            self.state = State.ERROR

        super().cleanup()

        if not self.state == State.ERROR:
            self.state = State.CLEANEDUP

    def _add_env(self, key, value=None):
        """Environment variable to be added to the container.
        If value is None, then the value should be taken from the current host
        """

        if value is None:
            opt = ["--env", key]
        else:
            opt = ["--env", f"{key}={value}"]
        self.podman_opts += opt

    def _setup_zap_podman_id_mapping_cli(self):
        """Adds a specific user mapping to the Zap podman container.
        The reason why it is needed is that the `zap` command do not run as the main user, but as the `zap` user (UID 1000)
        As a result, the resulting files can't be deleted by the host user.
        This function aims as preparing a specific UID/GID mapping so that the `zap` user maps to the host user
        source of the hack :
        https://github.com/containers/podman/blob/main/troubleshooting.md#39-podman-run-fails-with-error-unrecognized-namespace-mode-keep-iduid1000gid1000-passed
        """

        sizes = (
            subprocess.run(
                [
                    "podman",
                    "info",
                    "--format",
                    "{{ range .Host.IDMappings.UIDMap }}+{{ .Size }}{{ end }}",
                ],
                stdout=subprocess.PIPE,
            )
            .stdout.decode("utf-8")
            .strip("\n")
        )
        logging.debug(f"UIDmapping sizes: {sizes}")
        subuidSize = eval(f"{sizes} - 1")
        sizes = (
            subprocess.run(
                [
                    "podman",
                    "info",
                    "--format",
                    "{{ range .Host.IDMappings.GIDMap }}+{{ .Size }}{{ end }}",
                ],
                stdout=subprocess.PIPE,
            )
            .stdout.decode("utf-8")
            .strip("\n")
        )
        logging.debug(f"UIDmapping sizes: {sizes}")
        subgidSize = eval(f"{sizes} - 1")

        runas_uid = 1000
        runas_gid = 1000

        # UID mapping
        self.podman_opts += ["--uidmap", f"0:1:{runas_uid}"]
        self.podman_opts += ["--uidmap", f"{runas_uid}:0:1"]
        self.podman_opts += [
            "--uidmap",
            f"{runas_uid+1}:{runas_uid+1}:{subuidSize-runas_uid}",
        ]

        # GID mapping
        self.podman_opts += ["--gidmap", f"0:1:{runas_gid}"]
        self.podman_opts += ["--gidmap", f"{runas_gid}:0:1"]
        self.podman_opts += [
            "--gidmap",
            f"{runas_gid+1}:{runas_gid+1}:{subgidSize-runas_gid}",
        ]

        logging.debug(f"podman enabled UID/GID mapping arguments")

    def _paths_h2c(self, path):
        """Given a path on the host, find out what will be its path in the container, based on mapping
        WARNING: no support for subvolumes. we would need to find the "best match"
        """
        path = PosixPath(path).resolve()
        for h, c in self.volume_map.items():
            # force resolution to make sure we work with absolute paths
            h = PosixPath(h).resolve()

            # PurePath.is_relative_to() was added in python 3.9, so we have to use `parents` for now
            if h == path or h in path.parents:
                # match! replace the host path by the container path
                path = PurePosixPath(c, path.relative_to(h))
                return str(path)

        raise RuntimeError(
            f"_paths_h2c(): unable to find a volume map for path {path}",
            f"map list: {self.volume_map.keys()}",
        )

    def _paths_c2h(self, path):
        """Given a path on the container, find out what will be its path in the host, based on mapping
        WARNING: no support for subvolumes. we would need to find the "best match"
        """
        path = PurePosixPath(path)
        for h, c in self.volume_map.items():
            c = PurePosixPath(c)

            # PurePath.is_relative_to() was added in python 3.9 only, so we have to use `parents` for now
            if c == path or c in path.parents:
                # match! replace the container path by the host path
                path = PosixPath(h, path.relative_to(c))
                return str(path)

        raise RuntimeError(
            f"_paths_c2h(): unable to find a volume map for path {path}",
            f"container map list: {self.volume_map.values()}",
        )

    def _include_file(self, host_path, container_path=None):
        """Copies the file from host_path on the host to container_path in the container
        Notes:
            - MUST be run after the mapping is done
            - If container_path evaluates to False, default to `RESULTS_CONTAINER_DIR`
            - If container_path is a directory, copy the file to it without renaming it
        """
        if not container_path:
            container_path = RESULTS_CONTAINER_DIR

        # 1. find the host path to container_path and see if it's an existing directory
        path_to_dest = self._paths_c2h(container_path)
        if os.path.isdir(path_to_dest):
            path_to_dest = os.path.join(path_to_dest, os.path.basename(host_path))

        shutil.copy(host_path, path_to_dest)
        logging.debug(f"_include_file() created file '{path_to_dest}'")

    def _generate_file(self, data, container_path):
        """Generates a file (named `container_path` in the container), based on `data`
        Similar to _include_file, but from a stream instead of a host path
        Notes:
            - MUST be run after the mapping is done
            - container_path MUST be a path
        """
        host_path = self._paths_c2h(container_path)
        with open(host_path, "w") as f:
            f.write(data)
        logging.debug(f"_generate_file() created file '{host_path}'")

    def _add_volume(self, host_dir, cont_dir):
        """Adds a mapping from host_dir to cont_dir"""

        self.volume_map[host_dir] = cont_dir
        self.podman_opts += ["--volume", f"{host_dir}:{cont_dir}:Z"]
