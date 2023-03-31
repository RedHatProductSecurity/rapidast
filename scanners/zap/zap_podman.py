import logging
import pprint
import random
import shutil
import string
import subprocess

from .zap import MODULE_DIR
from .zap import Zap
from scanners import State
from scanners.path_translators import make_mapping_for_scanner

CLASSNAME = "ZapPodman"


pp = pprint.PrettyPrinter(indent=4)


class ZapPodman(Zap):
    ###############################################################
    # PRIVATE CONSTANTS                                           #
    # Accessed by ZapPodman only                                  #
    ###############################################################
    DEFAULT_IMAGE = "docker.io/owasp/zap2docker-stable:latest"

    ###############################################################
    # PROTECTED CONSTANTS                                         #
    # Accessed by parent Zap object                               #
    ###############################################################

    def __init__(self, config):
        """Initialize all vars based on the config.
        The code of the function only deals with the "podman" layer, the "ZAP" layer is handled by super()
        """

        logging.debug("Initializing podman-based ZAP scanner")
        super().__init__(config)

        # Setup defaults specific to Podman
        self.config.set(
            "scanners.zap.container.parameters.image",
            ZapPodman.DEFAULT_IMAGE,
            overwrite=False,
        )
        self.config.set(
            "scanners.zap.container.parameters.executable", "zap.sh", overwrite=False
        )

        # This will contain all the podman options
        self.podman_opts = []

        # Container name in the form 'rapidast_zap_<app-shortName>_<random-chars>
        self.container_name = "rapidast_zap_{}_{}".format(
            self.config.get("application.shortName"),
            "".join(random.choices(string.ascii_letters, k=6)),
        )

        # prepare the host <-> container mapping
        # The default location for WORK can be chosen by parent itself (no overide of self._create_work_dir)
        self.path_map = make_mapping_for_scanner(
            "Zap",
            ("workdir", self._create_work_dir(), "/zap/results"),
            ("scripts", f"{MODULE_DIR}/scripts", "/zap/scripts"),
            ("policies", f"{MODULE_DIR}/policies", "/home/zap/.ZAP/policies/"),
        )

    ###############################################################
    # PUBLIC METHODS                                              #
    # Accessed by RapiDAST                                        #
    # + MUST be implemented                                       #
    # + SHOUT call super().<method>                               #
    # + list: setup(), run(), postprocess(), cleanup()            #
    ###############################################################

    def setup(self):
        """Prepares everything:
        - the command line to run
        - environment variables
        - files & directory

        The code of the function only deals with the "podman" layer, the "ZAP" layer is handled by super()
        """

        if self.state != State.UNCONFIGURED:
            raise RuntimeError(f"ZAP setup encounter an unexpected state: {self.state}")

        self._setup_podman_cli()

        super().setup()

        if self.state != State.ERROR:
            self.state = State.READY

    def run(self):
        """If the state is READY, run the final podman run command.
        There is no need to call super() here.
        """
        logging.info("Running up the ZAP scanner in podman")
        if not self.state == State.READY:
            raise RuntimeError("[ZAP SCANNER]: ERROR, not ready to run")

        cli = ["podman", "run"]
        cli += self.podman_opts
        cli.append(
            self.config.get(
                "scanners.zap.container.parameters.image",
                default=ZapPodman.DEFAULT_IMAGE,
            )
        )

        if self.config.get("scanners.zap.additionalOptions.updateAddons", default=True):
            # Update scanner as a first command, then actually run ZAP
            # currently, this is done via a `sh -c` wrapper
            commands = (
                self.config.get("scanners.zap.container.parameters.executable")
                + " -cmd -addonupdate; "
                + " ".join(self.zap_cli)
            )
            cli += ["sh", "-c", commands]
        else:
            cli += self.zap_cli

        # DO STUFF
        logging.info(f"Running ZAP with the following command:\n{cli}")
        result = subprocess.run(cli, check=False)
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
        logging.info("Running postprocess for the ZAP Podman environment")
        if not self.state == State.DONE:
            raise RuntimeError(
                "No post-processing as ZAP has not successfully run yet."
            )

        super().postprocess()

        if not self.state == State.ERROR:
            self.state = State.PROCESSED

    def cleanup(self):
        logging.info("Running cleanup for the ZAP Podman environment")

        if not self.state == State.PROCESSED:
            raise RuntimeError("No cleanning up as ZAP did not processed results.")

        logging.debug(f"Deleting temp directory {self._host_work_dir()}")
        shutil.rmtree(self._host_work_dir())

        logging.debug(f"Deleting podman container {self.container_name}")
        result = subprocess.run(
            ["podman", "container", "rm", self.container_name], check=False
        )
        if result.returncode:
            logging.warning(f"Failed to delete container {self.container_name}")
            self.state = State.ERROR

        super().cleanup()

        if not self.state == State.ERROR:
            self.state = State.CLEANEDUP

    ###############################################################
    # PROTECTED METHODS                                           #
    # Accessed by Zap parent only                                 #
    # + MUST be implemented                                       #
    ###############################################################

    def _add_env(self, key, value=None):
        """Environment variable to be added to the container.
        If value is None, then the value should be taken from the current host
        """
        if value is None:
            opt = ["--env", key]
        else:
            opt = ["--env", f"{key}={value}"]
        self.podman_opts += opt

    ###############################################################
    # PRITVATE METHODS                                            #
    # Accessed by this ZapPodman object only                      #
    ###############################################################

    def _setup_podman_cli(self):
        logging.info(
            f"Preparing a podman container for the zap image, called {self.container_name}"
        )

        self.podman_opts += ["--name", self.container_name]

        # UID/GID mapping, in case of older podman version
        self._setup_zap_podman_id_mapping_cli()

        # Volume mappings
        for mapping in self.path_map:
            self.podman_opts += [
                "--volume",
                f"{mapping.host_path}:{mapping.container_path}:Z",
            ]

    def _setup_zap_podman_id_mapping_cli(self):
        """Adds a specific user mapping to the Zap podman container.
        Needed because the `zap` command do not run as the main user, but as the `zap` user (UID 1000)
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
                check=True,
            )
            .stdout.decode("utf-8")
            .strip("\n")
        )
        logging.debug(f"UIDmapping sizes: {sizes}")
        subuid_size = eval(f"{sizes} - 1")
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
        subgid_size = eval(f"{sizes} - 1")

        runas_uid = 1000
        runas_gid = 1000

        # UID mapping
        self.podman_opts += ["--uidmap", f"0:1:{runas_uid}"]
        self.podman_opts += ["--uidmap", f"{runas_uid}:0:1"]
        self.podman_opts += [
            "--uidmap",
            f"{runas_uid+1}:{runas_uid+1}:{subuid_size-runas_uid}",
        ]

        # GID mapping
        self.podman_opts += ["--gidmap", f"0:1:{runas_gid}"]
        self.podman_opts += ["--gidmap", f"{runas_gid}:0:1"]
        self.podman_opts += [
            "--gidmap",
            f"{runas_gid+1}:{runas_gid+1}:{subgid_size-runas_gid}",
        ]

        logging.debug("podman enabled UID/GID mapping arguments")
