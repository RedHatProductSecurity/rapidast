#!/usr/bin/env python3
"""
# Convert a Nessus CSV report to SARIF format(stdout).
# A usage example (see options in the code):
#  $ convert_nessus_csv_to_sarify.py [-f <input.csv>] [--log-level=DEBUG]
# If `-f` is absent, or its value is `-`, CSV data will be read from STDIN
#
"""
import argparse
import csv
import json
import logging
import re
import sys


def map_level(risk):
    """
    Map severity to match SARIF level property
    """
    if risk is "Critical" or risk is "High":
        return "error"
    elif risk is "Medium":
        return "warning"
    elif risk is "Low":
        return "note"
    else:
        return "none"


def nessus_info(field_name, entry):
    """
    Extract scan details from Nessus Plugin 19506
    """
    # Match the field name with RegEx, then split it to extract
    # the value. Finally, strip all surrounding whitespace
    return re.compile(field_name + ".*\n").search(entry)[0].split(":")[1].strip()


def is_file(file_name):
    """
    Bool to determine if filename was provided
    """
    return file_name is not None and file_name != "-"


def uri(host, port):
    """
    Format URI from host and port
    """
    target = host
    # Ignore port if 0
    if port is not "0":
        target = target + ":" + port
    return target


def convert_csv_to_sarif(csv_file):
    """
    Convert CSV data to SARIF format.
    """

    # Start of template. Nessus and version provided as default values to be replaced
    sarif_template = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "Nessus", "version": "10.8", "rules": []}},
                "results": [],
            }
        ],
    }

    rule_ids = set()

    # Below used for logging purposes for file vs stdin
    if is_file(csv_file):
        logging.debug("Reading input from: %s", csv_file)
    else:
        logging.debug("Reading input from STDIN")

    with (
        open(csv_file, newline="", encoding="utf-8") if is_file(csv_file) else sys.stdin
    ) as report:
        reader = csv.DictReader(report)
        for row in reader:
            if row["Plugin ID"] == "19506":
                # This Plugin contains lots of details about scan to populate SARIF tool property
                sarif_template["runs"][0]["tool"]["driver"]["name"] = nessus_info(
                    "Scanner edition used", row["Plugin Output"]
                )
                sarif_template["runs"][0]["tool"]["driver"]["version"] = nessus_info(
                    "Nessus version", row["Plugin Output"]
                )
                # Adding fullname to include policy
                sarif_template["runs"][0]["tool"]["driver"][
                    "fullName"
                ] = f"{nessus_info('Scanner edition used',row['Plugin Output'])} {nessus_info('Nessus version', row['Plugin Output'])} {nessus_info('Scan policy used', row['Plugin Output'])} Policy"

            if row["Plugin ID"] not in rule_ids:
                new_rule = {
                    "id": row["Plugin ID"],
                    "name": row["Name"],
                    "shortDescription": {"text": row["Description"]},
                }
                sarif_template["runs"][0]["tool"]["driver"]["rules"].append(new_rule)
                rule_ids.add(row["Plugin ID"])

            artifact_location = uri(row["Host"], row["Port"])

            new_report = {
                "ruleId": row["Plugin ID"],
                "level": map_level(row["Risk"]),
                "message": {
                    "text": f"{row["Plugin Output"]}\n\nSolution: {row["Solution"]}"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": artifact_location}
                        }
                    }
                ],
            }

            sarif_template["runs"][0]["results"].append(new_report)

    return sarif_template


def main():
    """
    Parses arguments before converting Nessus CSV report to SARIF JSON format
    """
    # Parse command-line arguments
    parser = argparse.ArgumentParser(
        description="Convert JSON data to SARIF format with JSON block added to message."
    )
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

    sarif_data = convert_csv_to_sarif(args.filename)

    # Print the SARIF data
    print(json.dumps(sarif_data, indent=2))


if __name__ == "__main__":
    main()
