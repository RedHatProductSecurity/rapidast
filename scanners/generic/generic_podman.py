import logging
import pprint
import shlex
import subprocess

from scanners import State
from scanners.generic.generic import Generic
from scanners.podman_wrapper import PodmanWrapper

CLASSNAME = "GenericPodman"


pp = pprint.PrettyPrinter(indent=4)


class GenericPodman(Generic):
    ###############################################################
    # PRIVATE CONSTANTS                                           #
    # Accessed by genericPodman only                                  #
    ###############################################################

    ###############################################################
    # PROTECTED CONSTANTS                                         #
    # Accessed by parent generic object                               #
    ###############################################################

    def __init__(self, config, ident="generic"):
        """Initialize all vars based on the config.
        The code of the function only deals with the "podman" layer, the "generic" layer is handled by super()
        """

        logging.debug("Initializing podman-based generic scanner")
        # Initialize generic scanner
        super().__init__(config, ident)

        image = self.my_conf("container.parameters.image")
        if not image:
            logging.error(
                f"Generic podman scanner requires an image to load (`scanners.{self.ident}.container.parameters.image`)"
            )

        # Initialize podman
        self.podman = PodmanWrapper(
            app_name=self.config.get("application.shortName"),
            scan_name=self.ident,
            image=image,
        )

    ###############################################################
    # PUBLIC METHODS                                              #
    # Accessed by RapiDAST                                        #
    # + MUST be implemented                                       #
    # + SHOULD call super().<method>                              #
    # + list: setup(), run(), postprocess(), cleanup()            #
    ###############################################################

    def setup(self):
        """Prepares everything:
        - the command line to run
        - environment variables
        - files & directory

        The code of the function only deals with the "podman" layer, the "generic" layer is handled by super()
        """

        if self.state != State.UNCONFIGURED:
            raise RuntimeError(
                f"generic_podman setup encountered an unexpected state: {self.state}"
            )

        self._setup_podman_cli()
        self._setup_generic_cli()

        super().setup()

        if self.state != State.ERROR:
            self.state = State.READY

    def run(self):
        """If the state is READY, run the final podman run command.
        There is no need to call super() here.
        """
        logging.info("Running up the generic scanner in podman")
        if not self.state == State.READY:
            raise RuntimeError("[generic SCANNER]: ERROR, not ready to run")

        cli = self.podman.get_complete_cli(self.generic_cli)

        # The result is stdout if "results" is undefined or `*stdout`
        stdout_store = (
            subprocess.PIPE
            if not self.my_conf("results") or self.my_conf("results") == "*stdout"
            else None
        )

        # DO STUFF
        logging.info(f"Running generic with the following command:\n{cli}")
        scanning_stdout_results = ""
        with subprocess.Popen(
            cli, stdout=stdout_store, bufsize=1, universal_newlines=True
        ) as scanning:
            if stdout_store:
                logging.debug("Storing podman's standard output")
                for line in scanning.stdout:
                    print(line, end="")
                    scanning_stdout_results += line
        logging.debug(
            f"generic returned the following:\n=====\n{pp.pformat(scanning)}\n====="
        )

        if scanning.returncode in self.my_conf(
            "container.parameters.validReturns", [0]
        ):
            logging.info(
                f"The generic process finished correctly, and exited with code {scanning.returncode}"
            )
            self.state = State.DONE
        else:
            logging.warning(
                f"The generic process did not finish correctly, and exited with code {scanning.returncode}"
            )
            self.state = State.ERROR

        # If we captured an output, let's save it into a temporary file, and use that as a new result parameter
        if stdout_store:
            report_path = f"{self.workdir}/stdout-report.txt"
            with open(report_path, "w", encoding="utf-8") as results:
                results.write(scanning_stdout_results)
            # Now that the result is a file, change the config to point to it
            logging.debug(
                f"Overloading {self.ident} config result parameter to {report_path}"
            )
            self.set_my_conf("results", value=report_path, overwrite=True)

    def postprocess(self):
        logging.info("Running postprocess for the generic Podman environment")
        if not self.state == State.DONE:
            raise RuntimeError(
                "No post-processing as generic has not successfully run yet."
            )

        super().postprocess()

        if not self.state == State.ERROR:
            self.state = State.PROCESSED

    def cleanup(self):
        logging.info("Running cleanup for the generic Podman environment")

        if not self.state == State.PROCESSED:
            raise RuntimeError("No cleanning up as generic did not processed results.")

        if self.podman.delete_yourself():
            self.state = State.ERROR

        super().cleanup()

        if not self.state == State.ERROR:
            self.state = State.CLEANEDUP

    ###############################################################
    # PROTECTED METHODS                                           #
    # Accessed by generic parent only                                 #
    # + MUST be implemented                                       #
    ###############################################################

    def _setup_generic_cli(self):
        """
        Generate the main generic command line (not the container command).
        Uses super() to generate the generic part of the command
        """

        self.generic_cli = super()._setup_generic_cli()
        if isinstance(self.generic_cli, str):
            self.generic_cli = shlex.split(self.generic_cli)

        logging.debug(f"generic will run with: {self.generic_cli}")

    ###############################################################
    # PRITVATE METHODS                                            #
    # Accessed by this genericPodman object only                      #
    ###############################################################

    def _setup_podman_cli(self):
        """Prepare the podman command.
        The function does not return anything, but adds options to self.podman_opts
        """
        pod_name = self.my_conf("container.parameters.podName")
        if pod_name:
            # injecting the container in an existing pod
            self.podman.deploy_to_pod(pod_name)

        # Volume mappings
        for mapping in self.my_conf("container.parameters.volumes", default=[]):
            self.podman.add_volume_map(mapping)
