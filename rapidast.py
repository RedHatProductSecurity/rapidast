#!/usr/bin/env python3
import argparse
import json
import logging
import os
import pprint
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any
from typing import Dict
from urllib import request

import yaml
from dotenv import load_dotenv
from jsonschema import Draft202012Validator
from jsonschema import SchemaError
from jsonschema import validate
from jsonschema import ValidationError

import configmodel.converter
import scanners
from exports.defect_dojo import DefectDojo
from exports.google_cloud_storage import GoogleCloudStorage
from utils import add_logging_level


pp = pprint.PrettyPrinter(indent=4)


DEFAULT_CONFIG_FILE = os.path.join(os.path.dirname(__file__), "rapidast-defaults.yaml")
SENSITIVE_KEYS = {
    "password",
    "secret",
    "api_key",
    "token",
    "access_key",
    "private_key",
    "authorization",
    "proxy-authorization",
    "cookie",
    "x-api-key",
    "x-auth-token",
    "x-csrf",
    "x-csrf-token",
    "x-xsrf-token",
}


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


def load_config(config_file_location: str) -> Dict[str, Any]:
    return yaml.safe_load(load_config_file(config_file_location))


# pylint: disable=R0911
# too many return statements
def run_scanner(name, config, args, dedo_exporter=None):
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

    if typ == "podman":
        logging.warning("Podman mode is deprecated and will be removed in version 2.12")

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
    except OSError as e:
        logging.error(f"Caught exception: {e}")
        logging.error(f"Ignoring failed Scanner `{name}` of type `{typ}`")
        return 1
    except RuntimeError as e:
        logging.error(f"Caught exception: {e}")
        logging.error(f"Ignoring failed Scanner `{name}` of type `{typ}`")
        return 1

    # Part 2: setup the environment (e.g.: spawn a server)
    try:
        scanner.setup()
    except Exception as excp:  # pylint: disable=W0718
        logging.error(f"Failed to set up the scanner: {excp}")
        scanner.state = scanners.State.ERROR

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

    # Optional: Export the scanner result to DefectDojo if set
    # Note: Unlike exporting to GCS, this process needs to be run for each scanner,
    #   because DefectDojo can only process one type of scanner result at a time

    if dedo_exporter and hasattr(scanner, "data_for_defect_dojo"):
        logging.info("Exporting results to the Defect Dojo service as configured")

        if dedo_exporter.export_scan(*scanner.data_for_defect_dojo()) == 1:
            logging.error("Exporting results to DefectDojo failed")
            return 1

    return 0


def dump_redacted_config(config_file_location: str, destination_dir: str) -> bool:
    """
    Redacts sensitive parameters and values from a configuration file and writes the redacted
    version to a destination directory

    Args:
        config_file_location: The file path to the source configuration file
        destination_dir: The directory where the redacted configuration file should be saved

    """
    logging.info(f"Starting the redaction and dumping process for the configuration file: {config_file_location}")

    mask_value_str = "*****"

    def _mask_sensitive_data(data):
        """Recursively mask sensitive values in a dictionary or list."""

        if isinstance(data, dict):
            masked_data = {}
            for key, value in data.items():
                if key == "authentication" and isinstance(value, dict) and "parameters" in value:
                    # Mask all values inside "authentication" -> "parameters"
                    masked_data[key] = value.copy()
                    masked_data[key]["parameters"] = {param: mask_value_str for param in value["parameters"]}
                elif key.lower() in SENSITIVE_KEYS:
                    masked_data[key] = mask_value_str
                else:
                    masked_data[key] = _mask_sensitive_data(value)  # Recurse for nested structures
            return masked_data
        elif isinstance(data, list):
            return [_mask_sensitive_data(item) for item in data]  # Recurse for lists
        return data

    try:
        if not os.path.exists(destination_dir):
            os.makedirs(destination_dir)
            logging.info(f"Created destination directory: {destination_dir}")

        config = yaml.safe_load(load_config_file(config_file_location))

        logging.info(f"Redacting sensitive information from configuration {config_file_location}")
        redacted_config = _mask_sensitive_data(config)

        dest = os.path.join(destination_dir, os.path.basename(config_file_location))
        logging.info(f"Saving redacted configuration to {dest}")
        with open(dest, "w", encoding="utf-8") as file:
            yaml.dump(redacted_config, file)

        logging.info("Redacted configuration saved successfully")
        return True

    except (FileNotFoundError, yaml.YAMLError, IOError) as e:
        logging.error(f"Error occurred while dumping redacted config: {e}")
        return False


def dump_rapidast_redacted_configs(main_config_file_location: str, destination_dir: str):
    """
    Dumps redacted versions of the main and default configuration files to the destination directory.

    Args:
        main_config_file_location: The file path to the main configuration file.
        destination_dir: The directory where the redacted configuration files should be saved.
    """
    if not dump_redacted_config(main_config_file_location, destination_dir):
        logging.error("Failed to dump configuration. Exiting.")
        sys.exit(2)

    if os.path.exists(DEFAULT_CONFIG_FILE):
        if not dump_redacted_config(DEFAULT_CONFIG_FILE, destination_dir):
            logging.error("Failed to dump configuration. Exiting.")
            sys.exit(2)


def deep_traverse_and_replace_with_var_content(d: dict) -> dict:  # pylint: disable=C0103
    """
    Recursively traverse a dictionary and replace key-value pairs where the key ends with `_from_var`
    The value is replaced with the corresponding environment variable value if available.
    """
    suffix = "_from_var"
    keys_to_replace = [key for key in d if isinstance(key, str) and key.endswith(suffix)]

    for key in keys_to_replace:
        new_key = key[: -len(suffix)]

        try:
            env_value = os.environ[d[key]]
            d[new_key] = env_value
            del d[key]
        except KeyError:
            logging.error(
                f"""
                Environment variable '{d[key]}' referenced by key '{key}' could not be found.
                No configuration replacement will be made for this key. Please check your configuration and environment"
                """
            )

    for key, value in d.items():
        if isinstance(value, dict):
            deep_traverse_and_replace_with_var_content(value)
        elif isinstance(value, list):
            for i, item in enumerate(value):
                if isinstance(item, dict):
                    value[i] = deep_traverse_and_replace_with_var_content(item)

    return d


def validate_config(config: dict, schema_path: Path) -> bool:
    """
    Validate a configuration dictionary against a JSON schema file
    """
    try:
        logging.info("Validating configuration")
        with schema_path.open("r", encoding="utf-8") as file:
            schema = json.load(file)

        validate(instance=config, schema=schema, format_checker=Draft202012Validator.FORMAT_CHECKER)
        logging.info("Configuration is valid")
        return True
    except ValidationError as e:
        logging.error(f"Validation error: {e.message}, json_path: {e.json_path}")
    except SchemaError as e:
        logging.error(f"Schema error: {e.message}, json_path: {e.json_path}")
    except json.JSONDecodeError:
        logging.error(f"Failed to parse JSON schema: {schema_path}")
    except Exception as e:  # pylint: disable=W0718
        logging.error(f"Unexpected error: {e}")

    return False


def validate_config_schema(config_file) -> bool:
    config = yaml.safe_load(load_config_file(config_file))

    try:
        config_version = str(config["config"]["configVersion"])
    except KeyError:
        logging.error("Missing 'configVersion' in configuration")
        return False

    script_dir = Path(__file__).parent
    schema_path = script_dir / "config" / "schemas" / config_version / "rapidast_schema.json"

    if schema_path.exists():
        resolved_config = deep_traverse_and_replace_with_var_content(config)
        return validate_config(resolved_config, schema_path)
    else:
        logging.warning(f"Configuration schema missing: {schema_path}. Skipping validation")
    return False


# pylint: disable=R0912, R0915
# R0912(too-many-branches)
# R0915(too many statements)
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

    validate_config_schema(config_file)

    # Load config file
    try:
        config = configmodel.RapidastConfigModel(yaml.safe_load(load_config_file(config_file)))
    except yaml.YAMLError as exc:
        raise RuntimeError(f"YAML error in config {config_file}':\n {str(exc)}") from exc

    full_result_dir_path = get_full_result_dir_path(config)
    dump_rapidast_redacted_configs(config_file, full_result_dir_path)

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

    # Check DefectDojo export configuration
    dedo_exporter = None
    if config.get("config.defectDojo.url"):
        dedo_exporter = DefectDojo(
            config.get("config.defectDojo.url"),
            {
                "username": config.get("config.defectDojo.authorization.username", default=""),
                "password": config.get("config.defectDojo.authorization.password", default=""),
            },
            config.get("config.defectDojo.authorization.token"),
            config.get("config.defectDojo.ssl", default=True),
        )

    # Check GCS export configuration
    gcs_exporter = None
    if config.get("config.googleCloudStorage.bucketName"):
        gcs_exporter = GoogleCloudStorage(
            bucket_name=config.get("config.googleCloudStorage.bucketName"),
            app_name=config.get_official_app_name(),
            directory=config.get("config.googleCloudStorage.directory", None),
            keyfile=config.get("config.googleCloudStorage.keyFile", None),
        )

    # Run all scanners
    scan_error_count = 0
    for name in config.get("scanners"):
        logging.info(f"Next scanner: '{name}'")

        ret = run_scanner(name, config, args, dedo_exporter)
        if ret == 1:
            logging.info(f"scanner: '{name}' failed")
            scan_error_count = scan_error_count + 1
        else:
            logging.info(f"scanner: '{name}' completed successfully")

    # Export all the scan results to GCS
    # Note: This is done after all scanners have run,
    #   unlike the DefectDojo export which needs to be done at the individual scanner level.
    if gcs_exporter:
        try:
            gcs_exporter.export_scan(full_result_dir_path)
            logging.info("Export to Google Cloud Storage completed successfully")
        except Exception as e:  # pylint: disable=W0718
            logging.error("Export to Google Cloud Storage failed: %s", e)
    else:
        logging.debug("GCS exporter not configured; skipping export")

    if scan_error_count > 0:
        logging.warning(f"Number of failed scanners: {scan_error_count}")
        sys.exit(2)
    else:
        sys.exit(0)


if __name__ == "__main__":
    run()
