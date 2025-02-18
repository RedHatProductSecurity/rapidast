import logging
import os
import shutil
import subprocess
from dataclasses import dataclass

import dacite
import yaml

from configmodel import RapidastConfigModel
from scanners import RapidastScanner
from scanners import State


@dataclass
class GarakConfig:
    model_name: str
    model_type: str
    probe_spec: str = "all"  # all or a list of probes like "probe1,probe2"
    garak_executable_path: str = "/usr/local/bin/garak"


CLASSNAME = "Garak"

MODULE_DIR = os.path.dirname(__file__)


class Garak(RapidastScanner):
    """Scanner implementation for Garak LLM security testing tool."""

    GARAK_CONFIG_TEMPLATE = "garak-config-template.yaml"
    GARAK_RUN_CONFIG_FILE = "garak-run-config.yaml"
    TMP_REPORTS_DIRNAME = "garak_runs"

    def __init__(self, config: RapidastConfigModel, ident: str = "garak"):
        super().__init__(config, ident)  # create a temporary directory (cleaned up during cleanup)

        self.workdir = self._create_temp_dir("workdir")
        self.workdir_reports_dir = os.path.join(self.workdir, self.TMP_REPORTS_DIRNAME)

        garak_config_section = config.subtree_to_dict(f"scanners.{ident}")
        if garak_config_section is None:
            raise ValueError("'scanners.garak' section not in config")

        # XXX self.config is already a dict with raw config values
        self.cfg = dacite.from_dict(data_class=GarakConfig, data=garak_config_section)

        self.garak_cli = []
        self.automation_config = {}

    def setup(self):
        """Set up the Garak scanner configuration."""
        if self.state != State.UNCONFIGURED:
            raise RuntimeError(f"Garak scanning setup encountered an unexpected state: {self.state}")

        try:
            template_path = os.path.join(MODULE_DIR, self.GARAK_CONFIG_TEMPLATE)
            with open(template_path, "r", encoding="utf-8") as stream:
                self.automation_config = yaml.safe_load(stream)

            # Update values from the config template with user configured values
            self.automation_config.update(
                {
                    "plugins": {
                        "model_name": self.cfg.model_name,
                        "model_type": self.cfg.model_type,
                        "probe_spec": self.cfg.probe_spec,
                    },
                    "reporting": {"report_dir": self.workdir_reports_dir},
                }
            )

            # Write updated config
            garak_run_conf_path = os.path.join(self.workdir, self.GARAK_RUN_CONFIG_FILE)
            with open(garak_run_conf_path, "w", encoding="utf-8") as f:
                yaml.dump(self.automation_config, f)

        except yaml.YAMLError as exc:
            raise RuntimeError(f"Failed to parse config '{template_path}': {exc}") from exc

        self.garak_cli = [self.cfg.garak_executable_path, "--config", garak_run_conf_path]

        if self.state != State.ERROR:
            self.state = State.READY

    def run(self):
        if self.state != State.READY:
            raise RuntimeError(f"[Garak] unexpected state: READY != {self.state}")

        logging.info(f"Running Garak with the following command:\n{self.garak_cli}")

        try:
            result = subprocess.run(self.garak_cli, check=False)
            logging.debug(f"Garak returned the following:\n=====\n{result}\n=====")

            if result.returncode == 0:
                self.state = State.DONE
            else:
                logging.warning(f"The Garak process did not finish correctly, and exited with code {result.returncode}")
                self.state = State.ERROR

        except FileNotFoundError:
            logging.error(
                f"Garak is not found at {self.cfg.garak_executable_path}. Please ensure Garak is installed in your PATH"
            )
            self.state = State.ERROR
        except subprocess.SubprocessError as e:
            logging.error(f"Failed to run Garak process: {str(e)}")
            self.state = State.ERROR

    def postprocess(self):
        if not self.state == State.DONE:
            raise RuntimeError("No post-processing as Garak scanning has not successfully run yet.")

        super().postprocess()

        try:
            shutil.copytree(self.workdir_reports_dir, self.results_dir, dirs_exist_ok=True)
        # pylint: disable=broad-exception-caught
        except Exception as excp:
            logging.error(f"Unable to save results: {excp}")
            # pylint: disable=attribute-defined-outside-init
            # it's a false positive: it's defined in the RapidastScanner class
            self.state = State.ERROR

        if not self.state == State.ERROR:
            self.state = State.PROCESSED

    def cleanup(self):
        if not self.state == State.PROCESSED:
            raise RuntimeError(f"Unexpected state while cleaning up: PROCESSED != {self.state}")

        logging.debug(f"cleaning up: the tmp directory: {self.workdir}")
        shutil.rmtree(self.workdir)
