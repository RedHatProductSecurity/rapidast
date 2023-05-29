#!/usr/bin/env python3
import argparse
import logging
import os
import pprint
from datetime import datetime

import yaml
from dotenv import load_dotenv

import configmodel.converter
import scanners
from exports.defect_dojo import DefectDojo

pp = pprint.PrettyPrinter(indent=4)


def load_environment():
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


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Runs various DAST scanners against a defined target, as configured by a configuration file."
    )
    parser.add_argument(
        "--log-level",
        dest="loglevel",
        choices=["debug", "info", "warning", "error", "critical"],
        default="info",
        help="Level of verbosity",
    )
    parser.add_argument(
        "--config",
        dest="config_file",
        default="./config/config.yaml",
        type=argparse.FileType("r", encoding="utf-8"),
        help="Path to YAML config file",
    )
    parser.add_argument(
        "--no-cleanup",
        dest="no_cleanup",
        help="Scanners to not cleanup their environment. (might be useful for debugging purpose).",
        action="store_true",
    )

    args = parser.parse_args()
    args.loglevel = args.loglevel.upper()
    logging.basicConfig(format="%(levelname)s:%(message)s", level=args.loglevel)
    logging.debug(
        f"log level set to debug. Config file: '{parser.parse_args().config_file.name}'"
    )

    try:
        config = configmodel.RapidastConfigModel(
            yaml.safe_load(parser.parse_args().config_file)
        )
    except yaml.YAMLError as exc:
        raise RuntimeError(
            f"Something went wrong while parsing one of the config '{parser.parse_args().config_file}':\n {str(exc)}"
        ) from exc

    # Update to latest config schema if need be
    config = configmodel.converter.update_to_latest_config(config)

    config.set("config.results_dir", get_full_result_dir_path(config))

    logging.debug(
        f"The entire loaded configuration is as follow:\n=====\n{pp.pformat(config)}\n====="
    )

    # Do early: load the environment file if one is there
    load_environment()

    # Prepare Defect Dojo if configured
    if config.get("config.defectDojo.url"):
        defect_d = DefectDojo(
            config.get("config.defectDojo.url"),
            config.get("config.defectDojo.authorization.username"),
            config.get("config.defectDojo.authorization.password"),
            config.get("config.defectDojo.authorization.token"),
        )

    # Run all scanners
    for name in config.get("scanners"):
        logging.info(f"Next scanner: '{name}'")

        # Merge the "general" configuration into the scanner's config
        # (but without overwriting anything: scanner's config takes precedence over the general config)
        logging.debug(f"Merging general config into {name}'s config")
        config.merge(
            config.get("general", default={}),
            preserve=True,
            root=f"scanners.{name}",
        )

        class_ = scanners.str_to_scanner(
            name, config.get(f"scanners.{name}.container.type", default="podman")
        )

        # Part 1: create a instance based on configuration
        scanner = class_(config)

        # Part 2: setup the environment (e.g.: spawn a server)
        scanner.setup()

        logging.debug(scanner)

        # Part 3: run the actual scan
        if scanner.state == scanners.State.READY:
            scanner.run()
        else:
            logging.warning(f"scanner {name} is not in READY state: it will not be run")
            continue

        # Part 4: Post process
        if scanner.state == scanners.State.DONE:
            scanner.postprocess()
        else:
            logging.warning(f"scanner {name} is not in DONE state: no post processing")
            continue

        # Part 5: cleanup
        if not args.no_cleanup:
            scanner.cleanup()

        # Part 6: export to defect dojo, if the scanner is compatible
        if defect_d and hasattr(scanner, "data_for_defect_dojo"):
            defect_d.import_or_reimport_scan(*scanner.data_for_defect_dojo())
