import logging
import os
import shutil
import tempfile

from scanners import RapidastScanner


CLASSNAME = "Trivy"

# Helper: absolute path to this directory (which is not the current directory)
# Useful for finding files in this directory
MODULE_DIR = os.path.dirname(__file__)


class Trivy(RapidastScanner):
    ## CONSTANTS
    DEFAULT_CONTAINER = "podman"

    TMP_REPORTS_SUBDIR = "reports"

    ## FUNCTIONS
    def __init__(self, config):
        logging.debug("Initializing Trivy scanner")
        super().__init__(config)

        self.results_dir = os.path.join(
            self.config.get("config.results_dir", default="results"), "trivy"
        )

        # This is used to construct the trivy Automation config.
        # It will be saved to a file during setup phase
        # and used by the trivy command during run phase
        self.trivy_config = {}

        # When state is READY, this will contain the entire trivy command
        if self.config.get("scanners.trivy.container.parameters.executable") == "":
            logging.debug("Executable command is set to empty")
            self.trivy_cli = []
        else:
            self.trivy_cli = [
                self.config.get("scanners.trivy.container.parameters.executable")
            ]

        # Instanciate a PathMaps with predifined mapping IDs. They will be filled by the typed scanners
        # List important locations for host <-> container mapping point
        # + work: where data is stored:
        #   - Trivy config file, reports, evidence, etc. are beneath this path
        self.path_map = None  # to be defined by the typed scanner

    ###############################################################
    # PUBLIC METHODS                                              #
    # Called via inheritence only                                 #
    ###############################################################

    def setup(self):
        """
        This code handles only the "Trivy" layer, independently of the container used.
        This method should not be called directly, but only via super() from a child's setup()
        """
        logging.info("Preparing Trivy configuration")
        self._setup_trivy_cli()
        self._setup_report()

    def run(self):
        """This code handles only the "Trivy" layer, independently of the container used.
        This method should not be called directly, but only via super() from a child's setup()
        This method is currently empty as running entirely depends on the containment
        """
        pass

    def postprocess(self):
        logging.info(f"Extracting report, storing in {self.results_dir}")
        reports_dir = os.path.join(
            self.path_map.workdir.host_path, Trivy.TMP_REPORTS_SUBDIR
        )
        shutil.copytree(reports_dir, self.results_dir)

    def cleanup(self):
        """Generic trivy cleanup: should be called only via super() inheritance"""

        logging.debug(f"Deleting temp directory used {self.path_map.workdir.host_path}")
        shutil.rmtree(self.path_map.workdir.host_path)
        pass

    ###############################################################
    # PROTECTED METHODS                                           #
    # Called via trivy or inheritence only                          #
    # May be overloaded by inheriting classes                     #
    ###############################################################

    def _setup_trivy_cli_for_image_scan(self, cli_ops):
        self.trivy_cli.append("image")

        self.trivy_cli.extend(cli_ops)

        # scanners
        self.trivy_cli.append("--scanners=vuln")

        # report_format
        report_format = self.config.get("scanners.trivy.report.format", default="json")
        self.trivy_cli.append("--format=" + report_format)
        self.trivy_cli.append(
            f"--output={self.path_map.workdir.container_path}/{Trivy.TMP_REPORTS_SUBDIR}/"
            f"image-scan-{report_format}-result.json"
        )

        # image-name
        image_name = self.config.get("scanners.trivy.image.name")
        if image_name:
            self.trivy_cli.append(image_name)

    def _setup_trivy_cli(self):
        """prepare the trivy command: self.trivy_cli
        This is a list of strings, representing the entire Trivy command to match the desired run
        """

        # common options for both image and k8s(TBD)
        cli_ops = []

        # severity
        severity = self.config.get("scanners.trivy.report.severity")
        if severity:
            cli_ops.extend(["--severity", severity])

        # skip-db-update
        if self.config.get("scanners.trivy.miscOptions.skipDbUpdate"):
            cli_ops.extend(["--skip-db-update"])

        # Trivy is going to provde multiple layers: e.g. image, k8s
        # currently, supporting 'image' only.
        image_conf = self.config.get("scanners.trivy.image")
        if image_conf:
            self._setup_trivy_cli_for_image_scan(cli_ops)

        logging.debug(f"Trivy will run with: {self.trivy_cli}")

    def _setup_report(self):
        os.makedirs(
            os.path.join(self.path_map.workdir.host_path, Trivy.TMP_REPORTS_SUBDIR)
        )

    def _create_work_dir(self):
        """This function simply creates a temporary directory aiming at storing data in transit.
        Data such as: the AF configuration, evidence, reports, etc.
        This directory will be deleted during cleanup.
        Descendent classes *may* overload this directory (e.g.: if they can't map /tmp)
        """
        temp_dir = tempfile.mkdtemp(prefix=f"rapidast_{self.__class__.__name__}_")
        logging.debug(f"Temporary work directory for Trivy scanner in host: {temp_dir}")
        return temp_dir
