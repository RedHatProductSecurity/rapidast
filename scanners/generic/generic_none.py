import logging
import pprint
import shlex
import subprocess

from scanners import State
from scanners.generic.generic import Generic

CLASSNAME = "GenericNone"


pp = pprint.PrettyPrinter(indent=4)


class GenericNone(Generic):
    ###############################################################
    # PRIVATE CONSTANTS                                           #
    # Accessed by genericNone only                                  #
    ###############################################################
    DEFAULT_GENERIC_TOOL_DIR = "scanners/generic/tools/"
    ###############################################################
    # PROTECTED CONSTANTS                                         #
    # Accessed by parent generic object                               #
    ###############################################################

    def __init__(self, config, ident="generic"):
        """Initialize all vars based on the config.
        The code of the function only deals with the "no container" layer, the "generic" layer is handled by super()
        """

        logging.debug("Initializing a local instance of the generic scanner")

        self.generic_cli = ""
        self.state = State.UNCONFIGURED
        self.tool_dir = self.DEFAULT_GENERIC_TOOL_DIR

        super().__init__(config, ident)

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

        The code of the function only deals with the "no container" layer
        """

        if self.state != State.UNCONFIGURED:
            raise RuntimeError(
                f"generic_none setup encountered an unexpected state: {self.state}"
            )

        self._setup_generic_cli()

        logging.debug(f"tool_dir is set to {self.tool_dir}")
        self.tool_dir = self.my_conf("toolDir", self.DEFAULT_GENERIC_TOOL_DIR)

        super().setup()

        if self.state != State.ERROR:
            self.state = State.READY

    def run(self):
        """If the state is READY, run the final run command.
        There is no need to call super() here.
        """
        logging.info("Running up the generic scanner")
        if not self.state == State.READY:
            raise RuntimeError("[generic SCANNER]: ERROR, not ready to run")

        cli = self.generic_cli

        # The result is stdout if "results" is undefined or `*stdout`
        stdout_store = (
            subprocess.PIPE
            if not self.my_conf("results") or self.my_conf("results") == "*stdout"
            else None
        )

        # DO STUFF

        logging.info(f"Running a generic scan with the following command:\n{cli}")

        # run the command in the tool_dir

        scanning_stdout_results = ""
        with subprocess.Popen(
            cli,
            cwd=self.tool_dir,
            stdout=stdout_store,
            bufsize=1,
            universal_newlines=True,
        ) as scanning:
            if stdout_store:
                logging.debug("Storing standard output")
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
        logging.info("Running postprocess for the generic environment")
        if not self.state == State.DONE:
            raise RuntimeError(
                "No post-processing as generic has not successfully run yet."
            )

        super().postprocess()

        if not self.state == State.ERROR:
            self.state = State.PROCESSED

    def cleanup(self):
        logging.info("Running cleanup for the generic environment")

        if not self.state == State.PROCESSED:
            raise RuntimeError("No cleanning up as generic did not processed results.")

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

        self.generic_cli = self.my_conf("inline")
        if isinstance(self.generic_cli, str):
            self.generic_cli = shlex.split(self.generic_cli)

        logging.debug(f"generic will run with: {self.generic_cli}")
