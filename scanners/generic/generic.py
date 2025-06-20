import logging
import os
import pprint
import shutil

import dacite

from configmodel import deep_traverse_and_replace_with_var_content
from configmodel.models.general import ContainerType
from configmodel.models.scanners.generic import GenericConfig
from scanners import RapidastScanner
from scanners import State


CLASSNAME = "Generic"


pp = pprint.PrettyPrinter(indent=4)

# Helper: absolute path to this directory (which is not the current directory)
# Useful for finding files in this directory
MODULE_DIR = os.path.dirname(__file__)


class Generic(RapidastScanner):
    ###############################################################
    # PRIVATE CONSTANTS                                           #
    # Accessed by Generic only                                    #
    ###############################################################

    ###############################################################
    # PROTECTED CONSTANTS                                         #
    # Accessed by parent Generic object                           #
    ###############################################################

    def __init__(self, config, ident):
        logging.debug("Initializing Generic scanner")
        super().__init__(config, ident)

        # create a temporary directory (cleaned up during cleanup)
        self.workdir = self._create_temp_dir("workdir")

        # The command to run (excluding the "container" layer)
        self.generic_cli = []

        generic_config_section = config.subtree_to_dict(f"scanners.{ident}")
        if generic_config_section is None:
            raise ValueError(f"'scanners.{ident}' section not in config")

        dacite_config = dacite.Config(
            strict=True,
            type_hooks={
                # Dacite doesn't natively support enums, so we use `type_hooks` as a workaround
                # to properly resolve enum values
                # https://github.com/konradhalas/dacite/issues/61
                ContainerType: ContainerType
            },
        )
        processed_data = deep_traverse_and_replace_with_var_content(generic_config_section)
        self.cfg = dacite.from_dict(data_class=GenericConfig, data=processed_data, config=dacite_config)

    ###############################################################
    # PUBLIC METHODS                                              #
    # Called via inheritence only                                 #
    ###############################################################

    def setup(self):
        """Prepares everything:
        - the command line to run
        - environment variables
        - files & directory

        This code handles only the "Generic" layer, independently of the container used.
        This method should not be called directly, but only via super() from a child's setup()
        """
        logging.info("Preparing Generic configuration")

    def run(self):
        """This code handles only the "Generic" layer, independently of the container used.
        This method should not be called directly, but only via super() from a child's setup()
        This method is currently empty as running entirely depends on the containment
        """
        pass

    def postprocess(self):
        logging.info(f"Extracting report, storing in {self.results_dir}")
        result = self.my_conf("results")
        try:
            os.makedirs(self.results_dir, exist_ok=True)
            if os.path.isdir(result):
                shutil.copytree(result, self.results_dir, dirs_exist_ok=True)
            else:
                shutil.copy(result, self.results_dir)

        # pylint: disable=broad-exception-caught
        except Exception as excp:
            logging.error(f"Unable to save results: {excp}")
            # pylint: disable=attribute-defined-outside-init
            # it's a false positive: it's defined in the RapidastScanner class
            self.state = State.ERROR

        # Calling parent RapidastScanner postprocess
        super().postprocess()

    def cleanup(self):
        """Generic Generic cleanup: should be called only via super() inheritance"""
        shutil.rmtree(self.workdir)

    def data_for_defect_dojo(self):
        """Return a tuple containing:
        1) Metadata for the test (dictionary)
        2) Path to the result file (string)
        For additional info regarding the metadata, see the `import-scan`/`reimport-scan`
        endpoints (https://demo.defectdojo.org/api/v2/doc/)

        To "cancel", return the (None, None) tuple

        """
        if not self._should_export_to_defect_dojo():
            return None, None
        logging.debug("Preparing data for Defect Dojo")

        sarif_filename = os.path.basename(self.my_conf("results"))

        filename = f"{self.results_dir}/{sarif_filename}"
        logging.debug(f"export {filename} to defect dojo")

        data = {"scan_type": "SARIF"}

        return (self._fill_up_data_for_defect_dojo(data), filename)

    ###############################################################
    # PROTECTED METHODS                                           #
    # Called via Generic or inheritence only                      #
    # May be overloaded by inheriting classes                     #
    ###############################################################

    def _setup_generic_cli(self):
        """
        Complete the generic_cli list of Generic argument.
        This is must be overloaded by descendant, which optionally call this one
        If called, the descendant must fill at least the executable
        """
        return self.my_conf("container.parameters.command")

    # disabling these 2 rules only here since they might actually be useful else where
    # pylint: disable=unused-argument
    def _add_env(self, key, value=None):
        logging.warning("_add_env() was called on the parent Generic class. This is likely a bug. No operation done")

    ###############################################################
    # PRIVATE METHODS                                             #
    # Those are called only from Generic itself                   #
    ###############################################################

    ###############################################################
    # MAGIC METHODS                                               #
    # Special functions (other than __init__())                   #
    ###############################################################
