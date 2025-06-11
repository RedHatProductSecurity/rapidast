#!/usr/bin/env python3
import argparse
import json
import logging
import os
import pprint
import re
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any
from typing import Dict
from typing import List
from urllib import request

import dacite
import yaml
from dotenv import load_dotenv
from jsonschema import Draft202012Validator
from jsonschema import SchemaError
from jsonschema import validate
from jsonschema import ValidationError

import configmodel.converter
import scanners
from configmodel import deep_traverse_and_replace_with_var_content
from configmodel.models.exclusions import Exclusions
from exports.defect_dojo import DefectDojo
from exports.google_cloud_storage import GoogleCloudStorage
from utils import add_logging_level
from utils.cel_exclusions import CELExclusions


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


# pylint: disable=R0912, R0915, R0914
# R0912(too-many-branches)
# R0915(too many statements)
# R0914(too-many-local)
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
    scanner_results = {}

    for name in config.get("scanners"):
        start_time = time.time()
        start_time_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(start_time))
        logging.info(f"Scanner '{name}' started at: {start_time_str}")

        ret = run_scanner(name, config, args, dedo_exporter)

        end_time = time.time()
        end_time_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(end_time))
        duration = end_time - start_time
        logging.info(f"Scanner '{name}' finished at: {end_time_str}")
        logging.info(f"Scanner '{name}' took {duration:.2f} seconds to run")

        scanner_results[name] = {
            "start_time": start_time_str,
            "end_time": end_time_str,
            "duration": duration,
            "return_code": ret,
        }

        if ret == 1:
            logging.info(f"scanner: '{name}' failed")
            scan_error_count = scan_error_count + 1
        else:
            logging.info(f"scanner: '{name}' completed successfully")

    sarif_properties = generate_sarif_properties(config, scanner_results, "commit_sha.txt")

    input_report_filename = "rapidast-scan-results.sarif"
    output_report_filename = "rapidast-filtered-scan-results.sarif"

    input_report_path = os.path.join(full_result_dir_path, input_report_filename)
    output_report_path = os.path.join(full_result_dir_path, output_report_filename)

    merge_sarif_files(
        directory=full_result_dir_path,
        properties=sarif_properties,
        output_filename=input_report_path,
    )

    try:
        exclusions_config_data = config.conf.get("config", {}).get("results", {}).get("exclusions")

        if not exclusions_config_data:
            logging.info("Configuration section 'exclusions' not found in config.results")
        else:
            exclusions_config_data = config.conf["config"]["results"]["exclusions"]
            filter_config = dacite.from_dict(data_class=Exclusions, data=exclusions_config_data)

            filter_sarif_report(
                input_report_path=input_report_path,
                output_report_path=output_report_path,
                exclusions_config=filter_config,
            )
    except Exception as e:  # pylint: disable=W0718
        logging.error(f"An error occurred during SARIF report filtering: {e}")

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


def collect_sarif_files(directory: str) -> List[str]:
    """
    Collects all SARIF files within a specified directory and its subdirectories

    Args:
        directory: The directory to search for SARIF files
    """
    sarif_files = []
    for root, _, files in os.walk(directory):
        for file in files:
            filepath = os.path.join(root, file)
            if os.path.isfile(filepath) and (file.endswith(".sarif") or file.endswith(".sarif.json")):
                logging.info(f"Found SARIF file: {filepath}")
                sarif_files.append(filepath)

    if not sarif_files:
        logging.warning(f"No SARIF files found in directory: {directory}")

    return sarif_files


def filter_sarif_report(input_report_path: str, output_report_path: str, exclusions_config: Exclusions) -> None:
    """
    Applies exclusions to a SARIF report file and saves the result to a new file

    Args:
        input_report_path: The file path to the original SARIF report
        output_report_path: The file path where the filtered SARIF report will be saved
        exclusions_config: Configuration for filtering rules

    """

    if not os.path.exists(input_report_path):
        logging.error(f"Input SARIF report not found: {input_report_path}")
        raise FileNotFoundError(f"Input SARIF report not found: {input_report_path}")

    logging.info(f"Starting SARIF filtering from '{input_report_path}' to '{output_report_path}'.")

    try:
        with open(input_report_path, "r", encoding="utf-8") as file_handle:
            original_sarif_report_data = json.load(file_handle)
    except json.JSONDecodeError as e:
        logging.error(f"Failed to parse input SARIF file '{input_report_path}': {e}")
        raise
    except IOError as e:
        logging.error(f"Error reading input SARIF file '{input_report_path}': {e}")
        raise

    cel_exclusions_engine = CELExclusions(exclusions_config)
    filtered_sarif_report_data = cel_exclusions_engine.filter_sarif_results(original_sarif_report_data)

    try:
        with open(output_report_path, "w", encoding="utf-8") as file_handle:
            json.dump(filtered_sarif_report_data, file_handle, indent=2)
        logging.info(f"Filtered SARIF report successfully saved to: '{output_report_path}'")
    except IOError as e:
        logging.error(f"Error writing filtered SARIF report to '{output_report_path}': {e}")
        raise

    logging.info("SARIF filtering process completed")


def merge_sarif_files(directory: str, properties: dict, output_filename: str):
    """
    Merges multiple SARIF files found within a directory and adds custom properties to the merged output

    Args:
        directory: The directory to search for SARIF files. The function will recursively search subdirectories.
        properties: Arbitrary properties to add to the 'properties' section of the merged SARIF output.
                    This can include metadata about the scan, such as scanner versions, configurations, or timestamps.
        output_filename: The full path and filename for the output merged SARIF file
    """
    merged_runs = []
    for filename in collect_sarif_files(directory):
        try:
            with open(filename, "r", encoding="utf8") as f:
                data = json.load(f)
                if "runs" in data and isinstance(data["runs"], list):
                    merged_runs.extend(data["runs"])
                else:
                    logging.warning(f"SARIF file '{filename}' does not appear to have a top-level 'runs' array")

        except Exception as e:  # pylint: disable=W0718
            logging.error(f"Error reading SARIF file '{filename}': {e}")

    merged_sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": merged_runs,
        "properties": properties,
    }

    try:
        with open(output_filename, "w", encoding="utf8") as outfile:
            json.dump(merged_sarif, outfile, indent=2)
        logging.info(f"Successfully merged SARIF files into: {output_filename}")
    except Exception as e:  # pylint: disable=W0718
        logging.error(f"Error writing merged SARIF file: {e}")


def generate_sarif_properties(
    config: configmodel.RapidastConfigModel, scanner_results: dict, commit_sha_filename: str
) -> dict:
    """
    Generates the dictionary containing properties for the SARIF output

    Args:
        config: The RapiDAST configuration object
        scanner_results: A dictionary containing the results of each scanner
        commit_sha_filename: The name of the file containing the commit SHA
    """
    commit_sha = None
    try:
        with open(commit_sha_filename, "r", encoding="utf-8") as file:
            commit_sha = file.read().strip()
    except FileNotFoundError:
        logging.warning(f"File '{commit_sha_filename}' not found. Falling back to `null`")
    except Exception as e:  # pylint: disable=W0718
        logging.warning(f"An error occurred while reading '{commit_sha_filename}': {e}")

    sarif_properties = {
        "config_version": config.get("config.configVersion"),
        "scanner_results": scanner_results,
        "commit_sha": commit_sha,
    }
    return sarif_properties


if __name__ == "__main__":
    run()
