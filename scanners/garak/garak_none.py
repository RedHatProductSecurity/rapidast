import logging
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from dataclasses import field
from typing import Any
from typing import Dict
from typing import Optional

import dacite
import yaml
from packaging import version

from configmodel import RapidastConfigModel
from scanners import RapidastScanner
from scanners import State


@dataclass
# pylint: disable=too-many-instance-attributes
class GarakConfig:
    parameters: Optional[Dict[str, Any]] = field(default_factory=dict)

    # The path to the Garak executable
    executable_path: str = field(default="/usr/local/bin/garak")


CLASSNAME = "Garak"

MODULE_DIR = os.path.dirname(__file__)


class Garak(RapidastScanner):
    """Scanner implementation for Garak LLM security testing tool."""

    GARAK_RUN_CONFIG_FILE = "garak-run-config.yaml"
    TMP_REPORTS_DIRNAME = "garak_runs"
    MIN_GARAK_VERSION = "0.10.2"

    def _check_garak_version(self):
        try:
            result = subprocess.run([self.cfg.executable_path, "--version"], capture_output=True, text=True, check=True)
            version_match = re.search(r"v(\d+\.\d+\.\d+)", result.stdout.strip())
            if not version_match:
                raise ValueError(f"Could not find version number in output: {result.stdout}")

            current_version = version.parse(version_match.group(1))
            min_version = version.parse(self.MIN_GARAK_VERSION)

            if current_version < min_version:
                raise RuntimeError(
                    f"Garak version {current_version} is not supported. Version {min_version} or higher is required."
                )
        except FileNotFoundError as exc:
            raise RuntimeError(f"Garak is not found at {self.cfg.executable_path}") from exc
        except (subprocess.SubprocessError, IndexError, ValueError) as e:
            raise RuntimeError(f"Failed to check Garak version: {str(e)}") from e

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

        def _search_model_type(config):
            if isinstance(config, dict):
                for key, value in config.items():
                    if key == "model_type":
                        return True
                    if isinstance(value, dict):
                        if _search_model_type(value):  # Recursively search in sub-dictionaries
                            return True
            return False

        # Check Garak version
        self._check_garak_version()

        self.automation_config = self.cfg.parameters

        # Update reporting with RapiDAST workdir directory
        self.automation_config["reporting"] = {"report_dir": self.workdir_reports_dir}

        # XXX check at least if model_type is defined to prevent a Garak error in advance
        if not _search_model_type(self.automation_config):
            raise ValueError("model_type is not defined in the Garak configuration")

        try:
            garak_run_conf_path = os.path.join(self.workdir, self.GARAK_RUN_CONFIG_FILE)
            with open(garak_run_conf_path, "w", encoding="utf-8") as f:
                yaml.dump(self.automation_config, f)

        except yaml.YAMLError as exc:
            raise RuntimeError(f"Failed to write a Garak config: {exc}") from exc

        self.garak_cli = [self.cfg.executable_path, "--config", garak_run_conf_path]

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
                f"Garak is not found at {self.cfg.executable_path}. Please ensure Garak is installed in your PATH"
            )
            self.state = State.ERROR
        except subprocess.SubprocessError as e:
            logging.error(f"Failed to run Garak process: {str(e)}")
            self.state = State.ERROR

    def postprocess(self):
        if not self.state == State.DONE:
            raise RuntimeError("No post-processing as Garak scanning has not successfully run yet.")

        super().postprocess()

        # pylint: disable=broad-exception-caught
        try:
            shutil.copytree(self.workdir_reports_dir, self.results_dir, dirs_exist_ok=True)
        except FileNotFoundError as exc:
            logging.error(
                f"There is no result, possibly because the configuration is not fully set up to run a scan: {exc}"
            )
            self.state = State.ERROR
        except Exception as excp:
            logging.error(f"Unable to save results: {excp}")

            self.state = State.ERROR

        if not self.state == State.ERROR:
            self.state = State.PROCESSED

    def cleanup(self):
        if not self.state == State.PROCESSED:
            raise RuntimeError(f"Unexpected state while cleaning up: PROCESSED != {self.state}")

        logging.debug(f"cleaning up: the tmp directory: {self.workdir}")
        shutil.rmtree(self.workdir)
