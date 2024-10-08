#!/usr/bin/env python3
#######################################
#
# Convert a Trivy k8s json result to SARIF format(stdout).
# A usage example (see options in the code):
#  $ convert_trivy_k8s_to_sarify.py [-f <input.json>] [--log-level=DEBUG]
# If `-f` is absent, or its value is `-`, JSON data will be read from STDIN
#
#
import argparse
import json
import logging
import sys


def read_json_block(json_file):
    """
    Read JSON data from a file, or from STDIN.
    """
    if json_file is None or json_file == "-":
        logging.debug("Reading input from STDIN")
        data = sys.stdin.read()
    else:
        logging.debug(f"Reading input from '{json_file}'")
        with open(json_file, "r", encoding="utf-8") as f:
            data = f.read()
    return json.loads(data)


def convert_json_to_sarif(json_data):
    """
    Convert JSON data to SARIF format with JSON block added to message.
    """

    sarif_template = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "Trivy-k8s", "version": "0.49.1", "rules": []}},
                "results": [],
            }
        ],
    }

    if "Resources" not in json_data:
        return sarif_template

    rule_ids = set()

    for res in json_data["Resources"]:
        if "Results" not in res:
            continue

        for result in res["Results"]:
            if "Misconfigurations" not in result:
                continue

            artifact_location = result["Target"]
            for misconf in result["Misconfigurations"]:
                new_report = {
                    "ruleId": misconf["ID"],
                    "level": misconf["Severity"],
                    "message": {"text": misconf["Message"]},
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": artifact_location}}}],
                }

                # It is observed there are no "StartLine" exists and "Code.Lines" is null in the result file
                # We'll skip adding a "region" in this case.
                if "StartLine" not in misconf["CauseMetadata"]:
                    logging.debug("no start line is found")
                elif not misconf["CauseMetadata"]["Code"]["Lines"]:
                    logging.debug("Code.Lines is null")
                else:
                    new_report["locations"][0]["physicalLocation"]["region"] = {
                        "startLine": misconf["CauseMetadata"]["StartLine"],
                        "endLine": misconf["CauseMetadata"]["EndLine"],
                        "snippet": {"text": json.dumps(misconf["CauseMetadata"]["Code"]["Lines"])},
                    }

                if misconf["ID"] not in rule_ids:
                    new_rule = {
                        "id": misconf["ID"],
                        "name": misconf["Title"],
                        "shortDescription": {"text": misconf["Description"]},
                    }

                    sarif_template["runs"][0]["tool"]["driver"]["rules"].append(new_rule)
                    rule_ids.add(misconf["ID"])

                sarif_template["runs"][0]["results"].append(new_report)

    return sarif_template


def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Convert JSON data to SARIF format with JSON block added to message.")
    parser.add_argument(
        "-f",
        "--filename",
        type=str,
        required=False,
        default=None,
        help="Path to JSON file (if absent or '-': read from STDIN)",
    )
    parser.add_argument(
        "--log-level",
        dest="loglevel",
        choices=["DEBUG", "VERBOSE", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default="INFO",
        help="Level of verbosity",
    )

    args = parser.parse_args()

    logging.basicConfig(format="%(levelname)s:%(message)s", level=args.loglevel)

    json_data = read_json_block(args.filename)
    sarif_data = convert_json_to_sarif(json_data)

    # Print the SARIF data
    print(json.dumps(sarif_data, indent=2))


if __name__ == "__main__":
    main()
