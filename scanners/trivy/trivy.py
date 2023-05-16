import logging
import os
import pprint
import shutil
import tarfile
import tempfile
from base64 import urlsafe_b64encode
from collections import namedtuple

import yaml

from scanners import generic_authentication_factory
from scanners import RapidastScanner
from scanners.downloaders import authenticated_download_with_rtoken


CLASSNAME = "Trivy"


pp = pprint.PrettyPrinter(indent=4)

# Helper: absolute path to this directory (which is not the current directory)
# Useful for finding files in this directory
MODULE_DIR = os.path.dirname(__file__)


class Trivy(RapidastScanner):
    ## CONSTANTS
    
    TRIVY_TEMPLATE = "trivy-template.yaml"
    USER = "test1"

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

        # When state is READY, this will contain the entire trivy command that the container layer should run
        self.trivy_cli = []

        
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
        """Prepares everything:
        - the command line to run
        - environment variables
        - files & directory

        This code handles only the "Trivy" layer, independently of the container used.
        This method should not be called directly, but only via super() from a child's setup()
        """
        logging.info("Preparing Trivy configuration")
        self._setup_trivy_cli()
        self._setup_report()
        
        #self._setup_trivy_automation()

    def run(self):
        """This code handles only the "Trivy" layer, independently of the container used.
        This method should not be called directly, but only via super() from a child's setup()
        This method is currently empty as running entirely depends on the containment
        """
        pass

    def postprocess(self):
        logging.info(f"Extracting report, storing in {self.results_dir}")
        reports_dir = os.path.join(self.path_map.workdir.host_path, Trivy.TMP_REPORTS_SUBDIR)
        shutil.copytree(reports_dir, self.results_dir)


    def cleanup(self):
        """Generic trivy cleanup: should be called only via super() inheritance"""
        pass

    ###############################################################
    # PROTECTED METHODS                                           #
    # Called via trivy or inheritence only                          #
    # May be overloaded by inheriting classes                     #
    ###############################################################


    def _create_work_dir(self):
        """This function simply creates a temporary directory aiming at storing data in transit.
        Data such as: the AF configuration, evidence, reports, etc.
        This directory will be deleted during cleanup.
        Descendent classes *may* overload this directory (e.g.: if they can't map /tmp)
        """
        temp_dir = tempfile.mkdtemp(prefix=f"rapidast_{self.__class__.__name__}_")
        logging.debug(f"Temporary work directory for Trivy scanner in host: {temp_dir}")
        return temp_dir

    def _host_work_dir(self):
        """Shortcut to the host path of the work directory"""
        return self.path_map.workdir.host_path

    def _container_work_dir(self):
        """Shortcut to the container path of the work directory"""
        return self.path_map.workdir.container_path

    def _include_file(self, host_path, dest_in_container=None):
        """Copies the file from host_path on the host to dest_in_container in the container
        Notes:
            - MUST be run after the mapping is done
            - If dest_in_container evaluates to False, default to `PathIds.WORK`
            - If dest_in_container is a directory, copy the file to it without renaming it
        """
        # 1. Compute host path
        if not dest_in_container:
            path_to_dest = self._host_work_dir()
        else:
            path_to_dest = self.path_map.container_2_host(dest_in_container)

        try:
            shutil.copy(host_path, path_to_dest)
        except shutil.SameFileError:
            logging.debug(
                f"_include_file() ignoring '{host_path} → 'container:{path_to_dest}' as they are the same file"
            )
        logging.debug(f"_include_file() '{host_path} → 'container:{path_to_dest}'")

    ###############################################################
    # PRIVATE METHODS                                             #
    # Those are called only from Trivy itself                       #
    ###############################################################
    def _setup_trivy_automation(self):
        # Load the Automation template
        try:
            trivy_template = f"{MODULE_DIR}/{Trivy.TRIVY_TEMPLATE}"
            logging.debug("Load the Trivy configuration template")
            with open(trivy_template, "r") as stream:
                self.trivy_config = yaml.safe_load(stream)
        except yaml.YAMLError as exc:
            raise RuntimeError(
                f"Something went wrong while parsing the config '{trivy_template}':\n {str(exc)}"
            ) from exc

        # Create the Trivy configuration
        self._setup_basic_conf()
        
        # The Trivy config file should now be setup and ready to be written
        self._save_automation_file()

    def _setup_basic_conf(self):
        #WIP
        
        #trivy_conf = self.config.get("scanners.trivy")
    
        
        # kubeconfig
        # adding to cli
        kube_config_file = self.config.get("scanners.trivy.k8s.kubeconfig")
        if kube_config_file:
            self._include_file(kube_config_file, f"{self._container_work_dir()}/kube.config")
        
        
        # namespace
        self.trivy_config["kubernetes"]["namespace"] = self.config.get("scanners.trivy.k8s.namespace")
        
        # resource
        # adding to cli
        
        # format
        # TODO: support 'json' only
        self.trivy_config["format"] = 'json'
        
        # severity
        self.trivy_config["severity"] = self.config.get("scanners.trivy.k8s.severity")
        # scanners
        self.trivy_config["scan"]["scanners"] = self.config.get("scanners.trivy.k8s.scanners")
        
        # dbupdate
        self.trivy_config["db"]["skip-update"] = self.config.get("scanners.trivy.miscOptions.skipDbUpdate")        
            
        
    def _save_automation_file(self):
        """Save the Trivy template file """
        trivy_template_host_path = self.path_map.workdir.host_path + "/trivy-template.yaml"
        with open(trivy_template_host_path, "w") as f:
            f.write(yaml.dump(self.trivy_config))
        logging.info(f"Saved Trivy Template File in {trivy_template_host_path}")
        
    def _setup_trivy_cli(self):
        """prepare the trivy command: self.trivy_cli
        This is a list of strings, representing the entire Trivy command to match the desired run
        """

        
        ## image scan
        
        image_conf = self.config.get("scanners.trivy.image")
        if image_conf:
            if self.config.get("general.container.type") == "podman":
                # podman run <trivy_image> doesn't require 'trivy' command.
                self.trivy_cli = ["image"]
            else:
                self.trivy_cli = ["trivy image"]
                
            # scanners
            
            self.trivy_cli.extend(
                    ["--scanners=vuln"]
                )       

            # skip-db
            self.trivy_cli.extend(
                ["--skip-db-update"]
            )
            
            # format/report
            self.trivy_cli.extend(
                ["--format=json"]
            )
        
            
            self.trivy_cli.extend(
                [f"--output={self.path_map.workdir.container_path}/{Trivy.TMP_REPORTS_SUBDIR}/image-scan-result.json"]
            )
            
            
             
            # image-name
            image_name = self.config.get("scanners.trivy.image.name")
            if image_name:
                self.trivy_cli.extend(
                    [image_name]
                )            
                
        

    

        logging.debug(f"Trivy will run with: {self.trivy_cli}")

    

    def _setup_report(self):
        os.makedirs(os.path.join(self.path_map.workdir.host_path, Trivy.TMP_REPORTS_SUBDIR))