import json
import logging
import os
import shutil
import subprocess

import dacite

from configmodel import RapidastConfigModel
from configmodel import deep_traverse_and_replace_with_var_content
from configmodel.models.scanners.mcp import McpConfig
from scanners import RapidastScanner
from scanners import State


CLASSNAME = "Mcp"


class Mcp(RapidastScanner):
    """Scanner wrapper for mcp-security-scanner CLI (HTTP transport).

    Expects `mcp-scan` to be installed (or configurable via executable_path).
    Produces JSON or text reports; we copy outputs to results dir. If JSON contains
    a SARIF-like run, we leave merging to RapiDAST's existing SARIF collector.
    """

    DEFAULT_OUTPUT_FILE = "mcp_scan_report.json"

    def __init__(self, config: RapidastConfigModel, ident: str = "mcp"):
        super().__init__(config, ident)
        self.workdir = self._create_temp_dir("workdir")
        self.cfg = self._load_cfg(config, ident)
        self.cli = []

    def _load_cfg(self, config: RapidastConfigModel, ident: str) -> McpConfig:
        section = config.subtree_to_dict(f"scanners.{ident}")
        if section is None:
            raise ValueError(f"'scanners.{ident}' section not in config")
        processed = deep_traverse_and_replace_with_var_content(section)
        return dacite.from_dict(data_class=McpConfig, data=processed)

    def setup(self):
        if self.state != State.UNCONFIGURED:
            raise RuntimeError(f"[MCP] unexpected state in setup: {self.state}")

        params = self.cfg.parameters or {}

        # Build CLI: `mcp-scan scan --url <...> [--transport http] [--format json] [--output <file>] ...`
        executable = self.cfg.executable_path
        self.output_path = os.path.join(self.workdir, self.DEFAULT_OUTPUT_FILE)

        self.cli = [
            executable,
            "scan",
        ]

        # map commonly used params 1:1
        flag_map = {
            "url": "--url",
            "transport": "--transport",
            "format": "--format",
            "timeout": "--timeout",
            "verbose": "--verbose",
            "only_health": "--only-health",
            "session_id": "--session-id",
            "sse_endpoint": "--sse-endpoint",
            "auth_type": "--auth-type",
            "auth_token": "--auth-token",
            "token_url": "--token-url",
            "client_id": "--client-id",
            "client_secret": "--client-secret",
            "scope": "--scope",
            "explain": "--explain",
        }

        for key, flag in flag_map.items():
            if key in params and params[key] is not None:
                value = params[key]
                if isinstance(value, bool):
                    if value:
                        self.cli.append(flag)
                else:
                    self.cli.extend([flag, str(value)])

        # default to JSON output so RapiDAST can ingest artifacts; allow override via parameters.format
        if not any(p in self.cli for p in ("--format",)):
            self.cli.extend(["--format", "json"])

        # respect explicit output path if provided
        if "output" in params and params["output"]:
            self.output_path = params["output"]
        else:
            self.cli.extend(["--output", self.output_path])

        logging.info(f"Prepared MCP scan CLI: {self.cli}")

        self.state = State.READY

    def run(self):
        if self.state != State.READY:
            raise RuntimeError(f"[MCP] unexpected state in run: {self.state}")

        logging.info("Running mcp-security-scanner")
        try:
            result = subprocess.run(self.cli, check=False)
        except FileNotFoundError as exc:
            logging.error(
                f"MCP scanner executable not found at '{self.cfg.executable_path}'. Install mcp-security-scanner or adjust 'executable_path'"
            )
            raise RuntimeError("mcp-scan not found") from exc

        if result.returncode == 0:
            self.state = State.DONE
        else:
            logging.warning(f"mcp-scan exited with code {result.returncode}")
            self.state = State.ERROR

    def postprocess(self):
        if self.state != State.DONE:
            raise RuntimeError("No post-processing as MCP scanning has not successfully run yet.")

        super().postprocess()

        try:
            os.makedirs(self.results_dir, exist_ok=True)
            # Copy output report if present
            if os.path.isfile(self.output_path):
                dest = os.path.join(self.results_dir, os.path.basename(self.output_path))
                shutil.copy(self.output_path, dest)

                # If the report already is SARIF, nothing to do. If JSON with a 'runs' SARIF-like, leave as-is.
                # Otherwise, do minimal wrap: create an empty SARIF placeholder to not break merging.
                try:
                    with open(dest, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    if not (isinstance(data, dict) and "runs" in data):
                        sarif_path = os.path.join(self.results_dir, "mcp-empty.sarif.json")
                        with open(sarif_path, "w", encoding="utf-8") as f:
                            json.dump({"version": "2.1.0", "runs": []}, f)
                except Exception:  # pylint: disable=broad-exception-caught
                    logging.debug("Report is not JSON; skipping SARIF placeholder generation")
            else:
                logging.warning("MCP output file not found; producing empty SARIF placeholder")
                sarif_path = os.path.join(self.results_dir, "mcp-empty.sarif.json")
                with open(sarif_path, "w", encoding="utf-8") as f:
                    json.dump({"version": "2.1.0", "runs": []}, f)

        except Exception as exc:  # pylint: disable=broad-exception-caught
            logging.error(f"Unable to save MCP results: {exc}")
            self.state = State.ERROR

        if self.state != State.ERROR:
            self.state = State.PROCESSED

    def cleanup(self):
        if self.state != State.PROCESSED:
            raise RuntimeError(f"Unexpected state while cleaning up: PROCESSED != {self.state}")

        logging.debug(f"cleaning up: the tmp directory: {self.workdir}")
        shutil.rmtree(self.workdir, ignore_errors=True)


