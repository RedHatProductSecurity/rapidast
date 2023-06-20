#!/usr/bin/python
import argparse
import logging

import yaml

import configmodel.converter
from utils import add_logging_level


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="""Takes an older version of the config, updated it to latest, and store the results.
In the process any comments will be deleted. Please review any warnings or errors"""
    )
    parser.add_argument(
        "--log-level",
        dest="loglevel",
        choices=["debug", "verbose", "info", "warning", "error", "critical"],
        default="info",
        help="Level of verbosity",
    )
    parser.add_argument(
        "--in",
        dest="config_file",
        default="./config/config.yaml",
        type=argparse.FileType("r", encoding="utf-8"),
        help="Path to YAML config file",
    )
    parser.add_argument(
        "--out",
        dest="config_out",
        default="./config/updated.yaml",
        type=argparse.FileType("w", encoding="utf-8"),
        help="Path to where the updated config should be stored",
    )

    args = parser.parse_args()
    args.loglevel = args.loglevel.upper()
    add_logging_level("VERBOSE", logging.DEBUG + 5)
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

    yaml.dump(config.conf, args.config_out)
    args.config_out.close()
