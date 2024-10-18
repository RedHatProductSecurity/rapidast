#!/usr/bin/env python3
import argparse
import logging
import os
import pprint
import re
import shutil
import sys
from datetime import datetime
from urllib import request

import yaml
from dotenv import load_dotenv

import configmodel.converter
import scanners
from exports.defect_dojo import DefectDojo
from exports.google_cloud_storage import GoogleCloudStorage
from utils import add_logging_level

pp = pprint.PrettyPrinter(indent=4)


DEFAULT_CONFIG_FILE = os.path.join(os.path.dirname(__file__), "rapidast-defaults.yaml")


def load_environment(config):
    """Load the environment variables based on the config set in config.environ"""
    source = config.get("config.environ.envFile")
    if source:
        load_dotenv(source)
        logging.debug(f"Loaded dotenv from '{source}'")
    else:
        logging.debug("No environment loaded")


def get_full_result_dir_path(rapidast_config):
    # Enforced result layout:
    # {config.results_base_dir}/
    #   {application.shortName}/
    #       {DAST-<date-time>-RapiDAST-<application.shortName>}/
    #           <scanner-name>
    # This way each runs will get their own directory, and each scanner their own subdir

    scan_datetime_str = datetime.now().strftime("%Y%m%d-%H%M%S")

    app_name = rapidast_config.get("application.shortName", default="scannedApp")
    results_dir_path = os.path.join(
        rapidast_config.get("config.base_results_dir", default="./results"),
        app_name,
        f"DAST-{scan_datetime_str}-RapiDAST-{app_name}",
    )
    return results_dir_path


def load_config_file(config_file_location: str):
    if re.compile(r"^https?://").match(config_file_location):
        return request.urlopen(config_file_location)
    else:
        return open(config_file_location, mode="r", encoding="utf-8")


def run_scanner(name, config, args, scan_exporter):
    """given the config `config`, runs scanner `name`.
    Returns:
        0 for success
        1 for failure
    (in order to count the number of failure)
    """

    # Merge the "general" configuration into the scanner's config
    # (but without overwriting anything: scanner's config takes precedence over the general config)
    logging.debug(f"Merging general config into {name}'s config")
    config.merge(
        config.get("general", default={}),
        preserve=True,
        root=f"scanners.{name}",
    )

    typ = config.get(f"scanners.{name}.container.type", default="none")
    try:
        class_ = scanners.str_to_scanner(name, typ)
    except ModuleNotFoundError:
        logging.error(f"Scanner `{name.split('_')[0]}` of type `{typ}` does not exist")
        logging.error(f"Ignoring failed Scanner `name.split('_')[0]` of type `{typ}`")
        logging.error(f"Please verify your configuration file: `scanners.{name}`")
        return 1

    # Part 1: create a instance based on configuration
    try:
        scanner = class_(config, name)
    except OSError as excp:
        logging.error(excp)
        logging.error(f"Ignoring failed Scanner `{name}` of type `{typ}`")
        return 1

    # Part 2: setup the environment (e.g.: spawn a server)
    scanner.setup()

    logging.debug(scanner)

    # Part 3: run the actual scan
    if scanner.state == scanners.State.READY:
        scanner.run()
    else:
        logging.error(f"scanner {name} is not in READY state: it will not be run")
        return 1

    # Part 4: Post process
    # Even in case of error, some information will be stored in the result directory for troubleshooting
    scanner.postprocess()

    # Part 5: cleanup
    if not scanner.state == scanners.State.PROCESSED:
        logging.error(f"Something is wrong. Scanner {name} is not in PROCESSED state: the workdir won't be cleaned up")
        return 1

    if not args.no_cleanup:
        scanner.cleanup()

    # Part 6: export to defect dojo, if the scanner is compatible
    if scan_exporter and hasattr(scanner, "data_for_defect_dojo"):
        logging.info("Exporting results to the Defect Dojo service as configured")

        if scan_exporter.export_scan(*scanner.data_for_defect_dojo()) == 1:
            logging.error("Exporting results to DefectDojo failed")
            return 1

    return 0


def dump_redacted_config(config_file_location: str, destination_dir: str) -> bool:
    """
    Redacts sensitive parameters from a configuration file and writes the redacted
    version to a destination directory

    Args:
        config_file_location: The file path to the source configuration file
        destination_dir: The directory where the redacted configuration file should be saved

    """
    logging.info("Starting the redaction and dumping process for the configuration files")

    try:
        if not os.path.exists(destination_dir):
            os.makedirs(destination_dir)
            logging.info(f"Created destination directory: {destination_dir}")

        if os.path.exists(DEFAULT_CONFIG_FILE):
            logging.info(f"Copying default config file from {DEFAULT_CONFIG_FILE} to {destination_dir}")
            shutil.copy(DEFAULT_CONFIG_FILE, destination_dir)

        config = yaml.safe_load(load_config_file(config_file_location))

        logging.info(f"Redacting sensitive information from configuration {config_file_location}")
        for key in config.keys():
            if config[key].get("authentication") and config[key]["authentication"].get("parameters"):
                for param in config[key]["authentication"]["parameters"]:
                    config[key]["authentication"]["parameters"][param] = "*****"

        dest = os.path.join(destination_dir, os.path.basename(config_file_location))
        logging.info(f"Saving redacted configuration to {dest}")
        with open(dest, "w", encoding="utf-8") as file:
            yaml.dump(config, file)

        logging.info("Redacted configuration saved successfully")
        return True

    except (FileNotFoundError, yaml.YAMLError, IOError) as e:
        logging.error(f"Error occurred while dumping redacted config: {e}")
        return False


def run():
    parser = argparse.ArgumentParser(
        description="Runs various DAST scanners against a defined target, as configured by a configuration file."
    )
    parser.add_argument(
        "--log-level",
        dest="loglevel",
        choices=["debug", "verbose", "info", "warning", "error", "critical"],
        default="info",
        help="Level of verbosity",
    )
    parser.add_argument(
        "--config",
        dest="config_file",
        default="./config/config.yaml",
        help="URL or Path to YAML config file",
    )
    parser.add_argument(
        "--no-cleanup",
        dest="no_cleanup",
        help="Scanners to not cleanup their environment. (might be useful for debugging purpose).",
        action="store_true",
    )

    args = parser.parse_args()
    args.loglevel = args.loglevel.upper()
    add_logging_level("VERBOSE", logging.DEBUG + 5)
    logging.basicConfig(format="%(levelname)s:%(message)s", level=args.loglevel)
    config_file = parser.parse_args().config_file

    logging.debug(f"log level set to debug. Config file: '{config_file}'")

    # Load config file
    try:
        config = configmodel.RapidastConfigModel(yaml.safe_load(load_config_file(config_file)))
    except yaml.YAMLError as exc:
        dump_redacted_config(config_file, "./results")
        raise RuntimeError(f"YAML error in config {config_file}':\n {str(exc)}") from exc

    full_result_dir_path = get_full_result_dir_path(config)
    if not dump_redacted_config(config_file, full_result_dir_path):
        logging.error("Failed to dump configuration. Exiting.")
        sys.exit(2)

    # Optionally adds default if file exists (will not overwrite existing entries)
    if os.path.exists(DEFAULT_CONFIG_FILE):
        logging.info(f"Loading defaults from: {DEFAULT_CONFIG_FILE}")
        try:
            config.merge(yaml.safe_load(load_config_file(DEFAULT_CONFIG_FILE)), preserve=True)
        except yaml.YAMLError as exc:
            raise RuntimeError(f"YAML error in config {DEFAULT_CONFIG_FILE}':\n {str(exc)}") from exc

    # Update to latest config schema if need be
    config = configmodel.converter.update_to_latest_config(config)

    config.set("config.results_dir", full_result_dir_path)

    logging.debug(f"The entire loaded configuration is as follow:\n=====\n{pp.pformat(config)}\n=====")

    # Do early: load the environment file if one is there
    load_environment(config)

    # Prepare an export to Defect Dojo if one is configured.
    scan_exporter = None
    if config.get("config.googleCloudStorage.bucketName"):
        scan_exporter = GoogleCloudStorage(
            bucket_name=config.get("config.googleCloudStorage.bucketName", "default-bucket-name"),
            app_name=config.get_official_app_name(),
            directory=config.get("config.googleCloudStorage.directory", None),
            keyfile=config.get("config.googleCloudStorage.keyFile", None),
        )
    elif config.get("config.defectDojo.url"):
        scan_exporter = DefectDojo(
            config.get("config.defectDojo.url"),
            {
                "username": config.get("config.defectDojo.authorization.username", default=""),
                "password": config.get("config.defectDojo.authorization.password", default=""),
            },
            config.get("config.defectDojo.authorization.token"),
            config.get("config.defectDojo.ssl", default=True),
        )

    # Run all scanners
    scan_error_count = 0
    for name in config.get("scanners"):
        logging.info(f"Next scanner: '{name}'")

        ret = run_scanner(name, config, args, scan_exporter)
        if ret == 1:
            logging.info(f"scanner: '{name}' failed")
            scan_error_count = scan_error_count + 1
        else:
            logging.info(f"scanner: '{name}' completed successfully")

    if scan_error_count > 0:
        logging.warning(f"Number of failed scanners: {scan_error_count}")
        sys.exit(2)
    else:
        sys.exit(0)


if __name__ == "__main__":
    run()
