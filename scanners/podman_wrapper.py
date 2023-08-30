import logging
import random
import shutil
import string
import subprocess

from utils import safe_add


class PodmanWrapper:
    ###############################################################
    # PRIVATE CONSTANTS                                           #
    # Accessed by PodmanWrapper only                              #
    ###############################################################

    ###############################################################
    # PROTECTED CONSTANTS                                         #
    # Accessed by parent scanner object                           #
    ###############################################################

    def __init__(self, app_name, scan_name, image):
        # First verify that "podman" can be called
        if not shutil.which("podman"):
            raise OSError(
                "Podman is not installed or not in the PATH. It is required to run a podman based scanner"
            )

        # Image to use
        self.image = image

        # This will contain all the podman options
        self.opts = []

        # Container name in the form 'rapidast_<app_name>_<scan_name>_<random-chars>
        random_chars = "".join(random.choices(string.ascii_letters, k=6))
        self.container_name = f"rapidast_{app_name}_{scan_name}_{random_chars}"
        self.add_option("--name", self.container_name)

    def get_complete_cli(self, cmd=None):
        """Returns an array representing the command that the caller should run
        `cmd` is the array of command that podman run should run
        DOES NOT RUN the command, only returns it as a list of strings
        """
        # can't set default to [] directly because of side-effects of mutables
        if cmd is None:
            cmd = []

        cli = ["podman", "run"] + self.opts + [self.image] + cmd
        logging.debug(f"The podman CLI: {cli}")
        return cli

    def delete_yourself(self):
        """Deletes the container image created by the run command"""
        ret = subprocess.run(
            ["podman", "rm", self.container_name], check=False
        ).returncode
        if ret:
            logging.warning(f"Failed to delete container {self.container_name}")
        return ret

    def add_option(self, option, val=None):
        """Adds a single argument to the cli"""
        if val is not None:
            self.opts.extend([option, val])
        else:
            self.opts.append(option)

    def deploy_to_pod(self, name=None):
        """Injects the container into a pre-existing pod.
        There is no verification that the pod exists
        This is incompatible with arguments related to pod creations, such as `--gidmap`
        Simply adds a `--pod <name>` to the arguments
        """
        if isinstance(name, str):
            self.add_option("--pod", name)

    def add_env(self, key, value=None):
        """Environment variable to be added to the container.
        If value is None, then the value should be taken from the current host
        """
        if value is None:
            self.add_option("--env", key)
        else:
            self.add_option("--env", f"{key}={value}")

    def add_volume_map(self, mapping):
        """Adds the `mapping` as a volume argument
        `mapping` is the fully formed string as passed to podman.
        WARNING: no verification is done. In particular, the `:Z` (SELinux) option fails on MacOS
        """
        self.add_option("--volume", mapping)

    def change_user_id(self, runas_uid, runas_gid):
        """Adds a specific user mapping between host user and user in the podman container.
        Some containers, such as Zap, focused on docker require this to prevent UID mismatch.
        This function aims as preparing a specific UID/GID mapping so that a particular UID/GID maps to the host user
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
                check=True,
            )
            .stdout.decode("utf-8")
            .strip("\n")
        )
        logging.debug(f"UIDmapping sizes: {sizes}")
        subuid_size = safe_add(f"{sizes} - 1")
        sizes = (
            subprocess.run(
                [
                    "podman",
                    "info",
                    "--format",
                    "{{ range .Host.IDMappings.GIDMap }}+{{ .Size }}{{ end }}",
                ],
                stdout=subprocess.PIPE,
                check=True,
            )
            .stdout.decode("utf-8")
            .strip("\n")
        )
        logging.debug(f"UIDmapping sizes: {sizes}")
        subgid_size = safe_add(f"{sizes} - 1")

        # UID mapping
        self.add_option("--uidmap", f"0:1:{runas_uid}")
        self.add_option("--uidmap", f"{runas_uid}:0:1")
        self.add_option(
            "--uidmap", f"{runas_uid+1}:{runas_uid+1}:{subuid_size-runas_uid}"
        )

        # GID mapping
        self.add_option("--gidmap", f"0:1:{runas_gid}")
        self.add_option("--gidmap", f"{runas_gid}:0:1")
        self.add_option(
            "--gidmap", f"{runas_gid+1}:{runas_gid+1}:{subgid_size-runas_gid}"
        )

        logging.debug("podman enabled UID/GID mapping arguments")
