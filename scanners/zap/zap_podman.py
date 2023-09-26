import logging
import platform
import pprint
import shutil
import subprocess

from .zap import MODULE_DIR
from .zap import Zap
from scanners import State
from scanners.path_translators import make_mapping_for_scanner
from scanners.podman_wrapper import PodmanWrapper

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

    def __init__(self, config, ident="zap"):
        """Initialize all vars based on the config.
        The code of the function only deals with the "podman" layer, the "ZAP" layer is handled by super()
        """

        logging.debug("Initializing podman-based ZAP scanner")
        # Initialize ZAP scanner
        super().__init__(config, ident)

        # Initialize podman
        self.podman = PodmanWrapper(
            app_name=self.config.get("application.shortName"),
            scan_name=self.ident,
            image=self.my_conf("container.parameters.image", ZapPodman.DEFAULT_IMAGE),
        )

        # Setup defaults specific to Podman
        self.config.set(
            f"scanners.{self.ident}.container.parameters.executable",
            "zap.sh",
            overwrite=False,
        )

        # prepare the host <-> container mapping
        # The default location for WORK can be chosen by parent itself (no overide of self._create_temp_dir)
        # To make things easier:
        #  - getters are created by the parents as shortcuts: self.(host|container)_(home|work|policies)_dir
        #  - the policies dir is relative to ZAP's home dir
        self.path_map = make_mapping_for_scanner(
            "Zap",
            ("workdir", self._create_temp_dir("workdir"), "/zap/results"),
            ("scripts", f"{MODULE_DIR}/scripts", "/zap/scripts"),
            ("zaphomedir", self._create_temp_dir("zaphomedir"), "/home/zap/.ZAP"),
        )
        logging.debug(f"ZAP workdir on host: {self.host_work_dir}")
        logging.debug(f"ZAP home on host: {self.host_home_dir}")

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

        # copy policy files so that they will be available in the container
        shutil.copytree(f"{MODULE_DIR}/policies", self.host_policies_dir)

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

        if self.my_conf("miscOptions.updateAddons", default=True):
            # Update scanner as a first command, then actually run ZAP
            # currently, this is done via a `sh -c` wrapper
            commands = (
                self.my_conf("container.parameters.executable")
                + " "
                + " ".join(self._get_standard_options())
                + " -cmd -addonupdate; "
                + " ".join(self.zap_cli)
            )
            cli = ["sh", "-c", commands]
        else:
            cli = self.zap_cli

        cli = self.podman.get_complete_cli(cli)

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

        if self.podman.delete_yourself():
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
        self.podman.add_env(key, value)

    def _setup_zap_cli(self):
        """
        Generate the main ZAP command line (not the container command).
        Uses super() to generate the generic part of the command
        """

        self.zap_cli = [self.my_conf("container.parameters.executable")]

        super()._setup_zap_cli()

        logging.debug(f"ZAP will run with: {self.zap_cli}")

    ###############################################################
    # PRITVATE METHODS                                            #
    # Accessed by this ZapPodman object only                      #
    ###############################################################

    def _setup_podman_cli(self):
        """Prepare the podman command.
        The function does not return anything, but adds options to self.podman
        """
        pod_name = self.my_conf("container.parameters.podName")
        if pod_name:
            # injecting the container in an existing pod
            self.podman.deploy_to_pod(pod_name)
        else:
            # UID/GID mapping, in case of older podman version
            # In the Zap image: this is uid=1000, gid=1000
            # note: this incompatible with pod injection,
            # in which case it needs to be done manually during the Pod creation
            self.podman.change_user_id(1000, 1000)

        # Volume mappings
        for mapping in self.path_map:
            vol_map = f"{mapping.host_path}:{mapping.container_path}"
            if platform.system() == "Darwin":
                logging.debug(
                    "Darwin(MacOS) is detected. Disabling Podman SELinux eXtented attributes for volume mapping"
                )
            else:
                vol_map += ":Z"

            self.podman.add_volume_map(vol_map)
