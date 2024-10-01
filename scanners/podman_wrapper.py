import json
import logging
import random
import shutil
import string
import subprocess


class PodmanWrapper:
    ###############################################################
    # PRIVATE CONSTANTS                                           #
    # Accessed by PodmanWrapper only                              #
    ###############################################################

    DEFAULT_ID_MAPPING_MAP_SIZE = 65536

    ###############################################################
    # PROTECTED CONSTANTS                                         #
    # Accessed by parent scanner object                           #
    ###############################################################

    def __init__(self, app_name, scan_name, image):
        # First verify that "podman" can be called
        if not shutil.which("podman"):
            raise OSError("Podman is not installed or not in the PATH. It is required to run a podman based scanner")

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
        ret = subprocess.run(["podman", "rm", self.container_name], check=False).returncode
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
        """
        Specify a container user ID to which the current user should be mapped to.
        This is sometimes required because rootless podman uses Linux' subUIDs.

        If podman version >= 4.3, use the `--userns keep-id:uid=X,gid=Y`
        otherwise, call `change_user_id_workaround()` to manually create a user mapping
        """
        logging.info(f"Current user mapped to container user {runas_uid}:{runas_gid}")
        try:
            vers = json.loads(
                subprocess.run(
                    ["podman", "version", "--format", "json"],
                    stdout=subprocess.PIPE,
                    check=True,
                ).stdout.decode("utf-8")
            )
            major, minor = map(int, vers["Client"]["Version"].split(".")[:2])
            logging.debug(f"podman version: {vers}. Major: {major}, minor: {minor}")
            if major < 4 or (major == 4 and minor < 3):
                # podman < 4.3.0 : the option `keep-id:uid=1000,gid=1000` is not present, we need a workaround
                self.change_user_id_workaround(runas_uid, runas_gid)
            else:
                # use option: keep-id:uid=1000,gid=1000
                self.add_option("--userns", f"keep-id:uid={runas_uid},gid={runas_gid}")

        except json.JSONDecodeError as exc:
            raise RuntimeError(f"Unable to parse `podman version` output: {exc}") from exc
        except (KeyError, AttributeError) as exc:
            raise RuntimeError(f"Unexpected podman version output: Version not found: {exc}") from exc
        except ValueError as exc:
            raise RuntimeError(
                f"Unexpected podman version output: unable to decode major/minor version: {exc}"
            ) from exc

    def change_user_id_workaround(self, runas_uid, runas_gid):
        """This function aims as preparing a specific UID/GID mapping so that a particular UID/GID maps to the host user
        Should be called only for podman < 4.3
        source of the hack :
        https://github.com/containers/podman/blob/main/troubleshooting.md#39-podman-run-fails-with-error-unrecognized-namespace-mode-keep-iduid1000gid1000-passed
        """
        subuid_size = self.DEFAULT_ID_MAPPING_MAP_SIZE - 1
        subgid_size = self.DEFAULT_ID_MAPPING_MAP_SIZE - 1

        try:
            info = json.loads(
                subprocess.run(
                    ["podman", "info", "--format", "json"],
                    stdout=subprocess.PIPE,
                    check=True,
                ).stdout.decode("utf-8")
            )
            logging.debug(f"podman UID mapping: {info['host']['idMappings']['uidmap']}")

            if info["host"]["idMappings"]["uidmap"] is not None:
                subuid_size = sum(i["size"] for i in info["host"]["idMappings"]["uidmap"]) - 1
            else:
                logging.warning(
                    f"the value of host.idMappings.uidmap in 'podman info' is null. \
                      Something might be wrong in your podman setup. If it's MacOS, try recreating podman machine. \
                      DEFAULT_MAP_SIZE {self.DEFAULT_ID_MAPPING_MAP_SIZE} applied"
                )
            if info["host"]["idMappings"]["gidmap"] is not None:
                subgid_size = sum(i["size"] for i in info["host"]["idMappings"]["gidmap"]) - 1
            else:
                logging.warning(
                    f"the value of host.idMappings.gidmap in 'podman info' is null. \
                    Something might be wrong in your podman setup. If it's MacOS, try recreating podman machine. \
                    DEFAULT_MAP_SIZE {self.DEFAULT_ID_MAPPING_MAP_SIZE} applied"
                )

        except json.JSONDecodeError as exc:
            raise RuntimeError(f"Unable to parse `podman info` output: {exc}") from exc
        except (KeyError, AttributeError) as exc:
            raise RuntimeError(f"Unexpected podman info output: entry not found: {exc}") from exc
        except Exception as exc:
            logging.error(f"change_user_id unexpected error: {exc}")
            raise RuntimeError(f"Unable to retrieve podman UID mapping: {exc}") from exc

        # UID mapping
        if subuid_size >= runas_uid:
            self.add_option("--uidmap", f"0:1:{runas_uid}")
            self.add_option("--uidmap", f"{runas_uid}:0:1")
            self.add_option("--uidmap", f"{runas_uid+1}:{runas_uid+1}:{subuid_size-runas_uid}")
            logging.debug("podman enabled UID mapping arguments (using uidmap workaround)")
        else:
            raise RuntimeError(
                "subUIDs seem to be disabled/misconfigured for the current user. \
                Rootless podman can not run without subUIDs"
            )

        # GID mapping
        if subgid_size >= runas_gid:
            self.add_option("--gidmap", f"0:1:{runas_gid}")
            self.add_option("--gidmap", f"{runas_gid}:0:1")
            self.add_option("--gidmap", f"{runas_gid+1}:{runas_gid+1}:{subgid_size-runas_gid}")
            logging.debug("podman enabled GID mapping arguments (using uidmap workaround)")
        else:
            raise RuntimeError(
                "subGIDs seem to be disabled/misconfigured for the current user. \
                Rootless podman can not run without subGIDs"
            )
