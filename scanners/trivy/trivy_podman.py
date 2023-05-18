import logging
import pprint
import random
import string
import subprocess

from .trivy import Trivy
from scanners import State
from scanners.path_translators import make_mapping_for_scanner

CLASSNAME = "TrivyPodman"


pp = pprint.PrettyPrinter(indent=4)


class TrivyPodman(Trivy):
    ###############################################################
    # PRIVATE CONSTANTS                                           #
    # Accessed by TrivyPodman only                                  #
    ###############################################################

    DEFAULT_IMAGE = "docker.io/aquasec/trivy:latest"

    ###############################################################
    # PROTECTED CONSTANTS                                         #
    # Accessed by parent Trivy object                               #
    ###############################################################

    def __init__(self, config):
        """Initialize all vars based on the config.
        The code of the function only deals with the "podman" layer, the "Trivy" layer is handled by super()
        """

        logging.debug("Initializing podman-based Trivy scanner")
        super().__init__(config)

        # Setup defaults specific to Podman
        self.config.set(
            "scanners.trivy.container.parameters.image",
            TrivyPodman.DEFAULT_IMAGE,
            overwrite=False,
        )

        # This will contain all the podman options
        self.podman_opts = []

        # Container name in the form 'rapidast_trivy_<app-shortName>_<random-chars>
        self.container_name = "rapidast_trivy_{}_{}".format(
            self.config.get("application.shortName"),
            "".join(random.choices(string.ascii_letters, k=6)),
        )

        # prepare the host <-> container mapping
        # The default location for WORK can be chosen by parent itself (no overide of self._create_work_dir)
        self.path_map = make_mapping_for_scanner(
            "Trivy",
            ("workdir", self._create_work_dir(), "/trivy/results"),
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

        The code of the function only deals with the "podman" layer, the "trivy" layer is handled by super()
        """

        if self.state != State.UNCONFIGURED:
            raise RuntimeError(
                f"Trivy setup encounter an unexpected state: {self.state}"
            )

        self._setup_podman_cli()

        super().setup()

        if self.state != State.ERROR:
            self.state = State.READY

    def run(self):
        """If the state is READY, run the final podman run command.
        There is no need to call super() here.
        """
        logging.info("Running up the Trivy scanner in podman")
        if not self.state == State.READY:
            raise RuntimeError("[Trivy SCANNER]: ERROR, not ready to run")

        cli = ["podman", "run"]
        cli += self.podman_opts
        cli.append(
            self.config.get(
                "scanners.trivy.container.parameters.image",
                default=TrivyPodman.DEFAULT_IMAGE,
            )
        )
        cli += self.trivy_cli

        # DO STUFF
        logging.info(f"Running trivy with the following command:\n{cli}")
        result = subprocess.run(cli, check=False)
        logging.debug(
            f"trivy returned the following:\n=====\n{pp.pformat(result)}\n====="
        )

        if result.returncode == 0:
            logging.info(
                f"The trivy process finished with no errors, and exited with code {result.returncode}"
            )
            self.state = State.DONE
        else:
            logging.warning(
                f"The trivy process did not finish correctly, and exited with code {result.returncode}"
            )
            self.state = State.ERROR

    def postprocess(self):
        logging.info("Running postprocess for the Trivy Podman environment")
        if not self.state == State.DONE:
            raise RuntimeError(
                "No post-processing as Trivy has not successfully run yet."
            )

        super().postprocess()

        if not self.state == State.ERROR:
            self.state = State.PROCESSED

    def cleanup(self):
        logging.info("Running cleanup for the Trivy Podman environment")

        if not self.state == State.PROCESSED:
            raise RuntimeError("No cleanning up as Trivy did not processed results.")

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
    # PRITVATE METHODS                                            #
    # Accessed by this trivyPodman object only                      #
    ###############################################################

    def _setup_podman_cli(self):
        logging.info(
            f"Preparing a podman container for the trivy image, called {self.container_name}"
        )

        self.podman_opts += ["--name", self.container_name]

        # Volume mappings
        for mapping in self.path_map:
            self.podman_opts += [
                "--volume",
                f"{mapping.host_path}:{mapping.container_path}:Z",
            ]
