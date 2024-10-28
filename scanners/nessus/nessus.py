import logging
from dataclasses import dataclass
from typing import List

import dacite
import requests.exceptions
from py_nessus_pro import PyNessusPro

from scanners import RapidastScanner
from scanners import State


@dataclass
class NessusServerConfig:
    url: str
    username: str
    password: str


@dataclass
class NessusScanConfig:
    name: str
    folder: str
    policy: str
    targets: List[str]
    # reportPath: str


@dataclass
class NessusConfig:
    server: NessusServerConfig
    scan: NessusScanConfig


class Nessus(RapidastScanner):
    def __init__(self, config):
        super().__init__(config, ident="nessus")
        self.nessus_client = None
        nessus_config_section = config.get("scanners.nessus")
        if nessus_config_section is None:
            raise ValueError("'scanners.nessus' section not in config")
        self.config = dacite.from_dict(data_class=NessusConfig, data=nessus_config_section)
        self._connect()

    def _connect(self):
        try:
            self.nessus_client = PyNessusPro(
                self.config.server.url,
                self.config.server.username,
                self.config.server.password,
                log_level="debug",
            )
        except requests.exceptions.RequestException as e:
            logging.error(f"Failed to connect to {self.config.server.url}: {e}")
            raise

    def setup(self):
        if self.nessus_client is None:
            raise RuntimeError(f"Nessus client not connected: {self.state}")
        # # Create scan object for use by PyNessusPro
        # # Scan name, scan targets, and scan folder are all retrieved from config
        # scanID = nessus.new_scan(
        #     name=config.get("scan_name"),
        #     targets=config.get("scan_targets"),
        #     folder=config.get("scan_folder"),
        #     create_folder=True,
        # )
        #
        # # Set scan policy
        # # Scan policy is retrieved from config
        # # Special note: As implemented, only user-created scan policies seem to be identified and must be
        # # created with the name used in the config as a prerequisite
        # if config.get("scan_policy"):
        #     nessus.set_scan_policy(scan_id=scanID, policy=config.get("scan_policy"))
        self.state = State.READY

    def run(self):
        if self.state != State.READY:
            raise RuntimeError(f"[nessus] unexpected state: READY != {self.state}")
        # # State that we want the scan to launch immediately
        # nessus.set_scan_launch_now(scan_id=scanID, launch_now=True)
        #
        # # Tell nessus to create and launch the scan
        # nessus.post_scan(scan_id=scanID)
        #
        # # Wait for the scan to complete
        # while nessus.get_scan_status(scanID)["status"] not in ["completed", "canceled", "imported", "aborted"]:
        #     time.sleep(20)
        #     print(nessus.get_scan_status(scanID))

    def postprocess(self):
        # # After scan is complete, download report in csv, nessus, and html format
        # # Path and any folders must already exist in this implementation
        # scan_reports = nessus.get_scan_reports(scanID, config.get("report_path"))
        if not self.state == State.ERROR:
            self.state = State.PROCESSED

    def cleanup(self):
        if not self.state == State.PROCESSED:
            raise RuntimeError(f"[nessus] unexpected state: PROCESSED != {self.state}")
