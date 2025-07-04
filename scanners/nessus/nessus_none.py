import json
import logging
import time
from os import listdir
from os import path
from typing import Optional

import dacite
import requests.exceptions
from py_nessus_pro import PyNessusPro

from configmodel import RapidastConfigModel
from configmodel.models.scanners.nessus import NessusConfig
from scanners import RapidastScanner
from scanners import State
from scanners.authentication_factory import generic_authentication_factory
from scanners.nessus.tools.convert_nessus_csv_to_sarif import convert_csv_to_sarif


# XXX required by ./rapidast.py
CLASSNAME = "Nessus"

END_STATUSES = [
    "completed",
    "canceled",
    "imported",
    "aborted",
]


class Nessus(RapidastScanner):
    def __init__(self, config: RapidastConfigModel, ident: str = "nessus"):
        super().__init__(config, ident)
        self._nessus_client: Optional[PyNessusPro] = None
        self._scan_id: Optional[int] = None
        nessus_config_section = config.subtree_to_dict(f"scanners.{ident}")
        if nessus_config_section is None:
            raise ValueError(f"'scanners.{ident}' section not in config")

        # XXX self.config is already a dict with raw config values
        self.cfg = dacite.from_dict(data_class=NessusConfig, data=nessus_config_section)
        self._sleep_interval: int = 10

        self.authenticated = self.authentication_factory()

        self._connect()

    def _connect(self):
        logging.debug(f"Connecting to nessus instance at {self.cfg.server.url}")
        try:
            self._nessus_client = PyNessusPro(
                self.cfg.server.url,
                self.cfg.server.username,
                self.cfg.server.password,
                log_level="debug",
            )
        except requests.exceptions.RequestException as e:
            logging.error(f"Failed to connect to {self.cfg.server.url}: {e}")
            raise

    @property
    def nessus_client(self) -> PyNessusPro:
        if self._nessus_client is None:
            raise RuntimeError(f"Nessus client not connected: {self.state}")
        return self._nessus_client

    @property
    def scan_id(self) -> int:
        if self._scan_id is None:
            raise RuntimeError("scan_id is None")
        return self._scan_id

    @generic_authentication_factory()
    def authentication_factory(self):
        """This is the default function, attached to error reporting"""
        raise RuntimeError(
            f"The authentication option is not supported. "
            f"Input - type: {self.cfg.authentication.type}, params: {self.cfg.authentication.parameters}"
        )

    @authentication_factory.register(None)
    def authentication_set_anonymous(self):
        """No authentication: don't do anything"""
        logging.info("Nessus scan not configured with any auth")
        return False

    def setup(self):
        logging.debug(f"Creating new scan named {self.cfg.scan.folder}/{self.cfg.scan.name}")
        self._scan_id = self.nessus_client.new_scan(
            name=self.cfg.scan.name,
            targets=self.cfg.scan.targets_as_str(),
            folder=self.cfg.scan.folder,
            create_folder=True,
        )

        if self._scan_id < 0:
            raise RuntimeError(f"Unexpected scan_id {self.scan_id}")

        # only user-created scan policies seem to be identified and must be
        # created with the name used in the config as a prerequisite
        if self.cfg.scan.policy:
            logging.debug(f"Setting scan policy to {self.cfg.scan.policy}")
            self.nessus_client.set_scan_policy(scan_id=self.scan_id, policy=self.cfg.scan.policy)

        self.state = State.READY

    def run(self):
        if self.state != State.READY:
            raise RuntimeError(f"[nessus] unexpected state: READY != {self.state}")
        # State that we want the scan to launch immediately
        logging.debug("Launching scan")
        self.nessus_client.set_scan_launch_now(scan_id=self.scan_id, launch_now=True)

        # Tell nessus to create and launch the scan
        self.nessus_client.post_scan(scan_id=self.scan_id)

        # Wait for the scan to complete
        start = time.time()
        while self.nessus_client.get_scan_status(self.scan_id)["status"] not in END_STATUSES:
            if time.time() - start > self.cfg.scan.timeout:
                logging.error(f"Timeout {self.cfg.scan.timeout}s reached waiting for scan to complete")
                self.state = State.ERROR
                break

            time.sleep(self._sleep_interval)
            logging.debug(f"Waiting {self._sleep_interval}s for scan to finish")
            logging.info(self.nessus_client.get_scan_status(self.scan_id))

    def postprocess(self):
        # After scan is complete, download report in csv, nessus, and html format
        # Path and any folders must already exist in this implementation
        logging.debug("Retrieving scan reports")
        scan_reports = self.nessus_client.get_scan_reports(self.scan_id, self.results_dir)
        logging.debug(scan_reports)
        # Get filename
        csv_files = [file for file in listdir(scan_reports) if file.endswith(".csv")]
        for file in csv_files:
            sarif_output = convert_csv_to_sarif(path.join(scan_reports, file))
            # Save sarif file
            with open(
                path.join(scan_reports, file.replace(".csv", ".sarif.json")),
                "w",
                encoding="utf-8",
            ) as output:
                json.dump(sarif_output, output, indent=2)

        if not self.state == State.ERROR:
            self.state = State.PROCESSED

    def cleanup(self):
        logging.debug("cleaning up")
        if not self.state == State.PROCESSED:
            raise RuntimeError(f"[nessus] unexpected state: PROCESSED != {self.state}")
