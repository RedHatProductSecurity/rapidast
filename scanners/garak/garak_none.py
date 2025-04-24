import glob
import json
import logging
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from dataclasses import field
from typing import Any
from typing import Dict

import dacite
import yaml
from packaging import version

from configmodel import RapidastConfigModel
from scanners import RapidastScanner
from scanners import State


@dataclass
# pylint: disable=too-many-instance-attributes
class GarakConfig:
    parameters: Dict[str, Any] = field(default_factory=dict)

    # The path to the Garak executable
    executable_path: str = field(default="/usr/local/bin/garak")


CLASSNAME = "Garak"

MODULE_DIR = os.path.dirname(__file__)


class Garak(RapidastScanner):
    """Scanner implementation for Garak LLM security testing tool."""

    GARAK_RUN_CONFIG_FILE = "garak-run-config.yaml"
    TMP_REPORTS_DIRNAME = "garak_runs"
    MIN_GARAK_VERSION = "0.10.2"

    def garak_version(self):
        result = subprocess.run([self.cfg.executable_path, "--version"], capture_output=True, text=True, check=True)
        version_match = re.search(r"v(\d+\.\d+\.\d+(\.\d+)?)", result.stdout.strip())
        if not version_match:
            raise ValueError(f"Could not find version number in output: {result.stdout}")

        current_version = version.parse(version_match.group(1))

        return current_version

    def _check_garak_version(self):
        try:
            current_version = self.garak_version()
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

        # Check Garak version
        self._check_garak_version()

        self.automation_config = self.cfg.parameters

        # Update reporting with RapiDAST workdir directory
        self.automation_config["reporting"] = {"report_dir": self.workdir_reports_dir}

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

        logging.info("Starting conversion of Garak hitlog data into SARIF format")
        try:
            converter = GarakHitLogSarifConverter(garak_scanner=self)
            converter.load_convert_save_garak_sarif(search_dir=self.results_dir)
            logging.info("Conversion completed successfully. The SARIF file has been generated.")
        except Exception as e:  # pylint: disable=broad-exception-caught
            logging.error(f"Unable to convert hitlog to SARIF format: {e}")
            self.state = State.ERROR

        if not self.state == State.ERROR:
            self.state = State.PROCESSED

    def cleanup(self):
        if not self.state == State.PROCESSED:
            raise RuntimeError(f"Unexpected state while cleaning up: PROCESSED != {self.state}")

        logging.debug(f"cleaning up: the tmp directory: {self.workdir}")
        shutil.rmtree(self.workdir)


class GarakHitLogSarifConverter:
    def __init__(self, garak_scanner):
        self.garak = garak_scanner

    def load_convert_save_garak_sarif(self, search_dir: str = ".", hitlog_pattern: str = "*.hitlog.jsonl"):
        """
        Finds the latest Garak hitlog file (matching *hitlog.jsonl), loads it, converts it to SARIF,
        and saves the result as a .sarif file in the same directory.

        Raises:
            FileNotFoundError: If no matching hitlog file is found.
            ValueError: If the hitlog contains invalid JSON.
        """
        pattern = os.path.join(search_dir, hitlog_pattern)
        hitlog_files = glob.glob(pattern)
        hits = []

        if not hitlog_files:
            logging.info(
                f"No Garak hitlog files were found in '{search_dir}' matching the pattern '{hitlog_pattern}'. "
                f"An empty SARIF file will be generated to indicate no issues were detected"
            )
            pattern = os.path.join(search_dir, "*.report.jsonl")
            report_files = glob.glob(pattern)
            if not report_files:
                raise FileNotFoundError(f"No report file found in {search_dir}")
            report_files.sort(key=os.path.getmtime, reverse=True)
            selected_log = report_files[0]

        else:
            hitlog_files.sort(key=os.path.getmtime, reverse=True)

            selected_log = hitlog_files[0]

            with open(selected_log, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            hits.append(json.loads(line))
                        except json.JSONDecodeError as e:
                            raise ValueError(f"Invalid JSON in {selected_log}: {e}") from e

        sarif_data = self.convert_to_sarif(hits)

        sarif_path = selected_log.replace(".jsonl", ".sarif")
        with open(sarif_path, "w", encoding="utf-8") as f:
            json.dump(sarif_data, f, indent=2)

        return sarif_data, sarif_path

    def convert_to_sarif(self, hits: list[dict]) -> dict:
        """
        Convert a list of Garak LLM security scanner hit logs (JSONL-parsed as dicts) into SARIF format

        ---
        Garak HitLog Structure:
        - goal: Description of the LLM behavior being tested (e.g., "print escaped ANSI codes")
        - prompt: The model input
        - output: The model's generated response
        - trigger: Substring in output that triggered a match (optional)
        - score: Float between 0.0 and 1.0 indicating how successfully the output fulfilled the test goal
        - generator: The LLM backend used
        - probe: The test probe used (e.g., "ansiescape")
        - detector: The logic that flagged the output (e.g., "AnsiEscaped")
        - run_id: A unique identifier for the scan run
        - attempt_id/seq: ID and sequence for a specific attempt to test a prompt (https://reference.garak.ai/en/latest/attempt.html)
        - generations_per_prompt: The number of generations per prompt, basically, how many times it tried the same prompt
        ---
        SARIF Mappings:
        - `probe` + `detector` → `ruleId`: This forms a composite unique rule identifier for each detection type.
        - `goal` → `rule.shortDescription.text`: Human-readable description of what the rule is targeting.
        - `prompt` + `output` → `message.text`: Helpful for auditors to see the input and output in context.
        - `score` → `level`: ≥ 0.8 maps to "error", else "warning" to reflect severity.
        - All relevant metadata (`score`, `trigger`, `generator`, etc.) is stored under `properties` for traceability.
        """

        results = []
        rules_map = {}

        try:
            garak_version = str(self.garak.garak_version())
        except Exception:  # pylint: disable=broad-exception-caught
            garak_version = "unknown"

        for hit in hits:
            probe = hit.get("probe", "unknown")
            detector = hit.get("detector", "unknown")
            goal = hit.get("goal", "Unknown goal")
            rule_id = f"{probe}/{detector}"
            score = hit.get("score", 0.0)

            level = "error" if score >= 0.8 else "warning"

            if rule_id not in rules_map:
                rules_map[rule_id] = {"id": rule_id, "shortDescription": {"text": f"Garak probe for goal: {goal}"}}

            result = {
                "ruleId": rule_id,
                "level": level,
                "message": {"text": f"Prompt: {hit.get('prompt')}\nOutput: {hit.get('output')}"},
                "properties": {
                    "score": score,
                    "generator": hit.get("generator"),
                    "run_id": hit.get("run_id"),
                    "attempt_id": hit.get("attempt_id"),
                    "attempt_seq": hit.get("attempt_seq"),
                    "attempt_idx": hit.get("attempt_idx"),
                    "detector": hit.get("detector"),
                    "generations_per_prompt": hit.get("generations_per_prompt"),
                    "trigger": hit.get("trigger"),
                },
            }

            results.append(result)

        return {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Garak",
                            "fullName": "Garak, LLM vulnerability scanner",
                            "informationUri": "https://github.com/NVIDIA/garak",
                            "version": garak_version,
                            "rules": list(rules_map.values()),
                        }
                    },
                    "results": results,
                }
            ],
        }
