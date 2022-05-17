import argparse
import itertools
import logging
import os
import sys

import yaml

# TODO: Possibly something to solve here
try:
    from .lib import *
except ImportError:
    from lib import *

logging.basicConfig(level=logging.INFO)
logger = logging.Logger("GenZAPScriptMain")
logger.addHandler(logging.StreamHandler())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generate active and passive ZAP scripts"
    )
    parser.add_argument(
        "--rapidast-config",
        type=argparse.FileType("r"),
        default=None,
        help="RapiDAST configuration file, required for --delete-existing and --load-and-enable",
    )
    parser.add_argument(
        "--delete-existing",
        action="store_true",
        help="Delete previously generated ZAP scripts (active+passive)",
    )
    parser.add_argument(
        "--load-and-enable",
        action="store_true",
        help="Load and enable the generated ZAP script (if --delete-existing is specified it is executed first",
    )
    parser.add_argument(
        "--output",
        type=argparse.FileType("w"),
        default=None,
        help="Output file for generated ZAP script, default is not displayed",
    )
    parser.add_argument(
        "--script-description",
        type=str,
        default="Empty description",
        help="Script description in ZAP",
    )
    parser.add_argument("--debug", action="store_true", help="Print debug messages")
    parser.add_argument(
        "--from-yaml",
        type=argparse.FileType("r"),
        help="Import script definition from a YAML file",
    )

    # Finding
    def add_finding_group(parser):
        finding_group = parser.add_argument_group(title="Finding definition")
        finding_group.add_argument("--finding-title", type=str, required=True)
        finding_group.add_argument("--finding-description", type=str, default="")
        finding_group.add_argument(
            "--finding-confidence", type=int, choices=list(range(1, 4)), default=1
        )
        finding_group.add_argument(
            "--finding-risk", type=int, choices=list(range(0, 4)), default=1
        )

    # Active or Passive
    script_type = parser.add_subparsers(title="Script type", dest="script_type")

    # Active
    script_type_active = script_type.add_parser(
        "active", help="Script for ZAP active scanner"
    )
    add_finding_group(script_type_active)
    # Payloads
    payloads_group = script_type_active.add_argument_group(
        title="Payloads definition",
        description="Payloads are literals inserted or appended to URL/body parameters scanned by ZAP.",
    )
    payload_definition_group = payloads_group.add_mutually_exclusive_group(
        required=True
    )
    payload_definition_group.add_argument(
        "--payload",
        type=str,
        nargs="+",
        help="Payload(s) to insert/append to the scanned parameter",
    )
    payload_definition_group.add_argument(
        "--payload-file",
        type=argparse.FileType("r"),
        help="Payloads file, one per line, to insert/append to the scanned parameter",
    )
    # Payload insertion options
    payloads_group.add_argument(
        "--only-param",
        type=str,
        help="Only try payloads for parameters matching this regexp (default is all parameters)",
        default=".*",
    )
    payloads_group.add_argument(
        "--append-payload",
        default=False,
        action="store_true",
        help="Append Payloads to the parameter",
    )

    def msCheck(x):
        try:
            x = int(x)
            if x < 0:
                raise ValueError()
        except ValueError:
            raise argparse.ArgumentTypeError(
                "Positive integer expected for milliseconds count"
            )
        return x

    payloads_group.add_argument(
        "--time-between-requests",
        type=msCheck,
        default=500,
        help="Time between requests, in milliseconds",
    )
    # Response processing
    response_processing_group = script_type_active.add_argument_group(
        title="Response processing",
        description="Process responses to injected parameters",
    )
    search_in_choices = ["response.header", "response.body"]
    response_processing_group.add_argument(
        "--search-in",
        choices=search_in_choices,
        required=True,
        default="response.body",
        help="Where should the regexp be matched",
    )
    regexp_group = response_processing_group.add_mutually_exclusive_group(required=True)
    regexp_group.add_argument(
        "--regex", type=str, nargs="+", help="Regular Expression to evaluate"
    )
    regexp_group.add_argument(
        "--regex-file", type=str, help="Regular Expressions to evaluate, one per line"
    )

    # Passive
    script_type_passive = script_type.add_parser(
        "passive", help="Script for ZAP passive scanner for HTTP requests or responses"
    )
    add_finding_group(script_type_passive)
    # Request/Response search definition
    search_group = script_type_passive.add_argument_group(title="Search definition")
    search_in_choices = ["request.method", "request.url"] + [
        ".".join(a)
        for a in itertools.product(*[["request", "response"], ["header", "body"]])
    ]
    search_group.add_argument(
        "--search-in",
        choices=search_in_choices,
        required=True,
        default="response.body",
        help="Where should the regexp be matched",
    )
    regexp_group = search_group.add_mutually_exclusive_group(required=True)
    regexp_group.add_argument(
        "--regex", type=str, nargs="+", help="Regular Expression to evaluate"
    )
    regexp_group.add_argument(
        "--regex-file", type=str, help="Regular Expressions to evaluate, one per line"
    )

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
    else:
        args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)

    def file_lines_or_default(fp, default_value):
        return ([x.rstrip() for x in fp.readlines()] if fp else default_value) or list()

    if args.from_yaml:
        yamlConf = yaml.safe_load(args.from_yaml)
        delattr(args, "from_yaml")

        for k, v in yamlConf.items():
            if isinstance(v, list):
                if not hasattr(args, k):
                    setattr(args, k, list())
                for val in v:
                    getattr(args, k).append(val)
            else:
                setattr(args, k, v)

        # Because yaml import don't require active/passive sub-parser to execute, we need some fixtures
        for a in filter(lambda b: not hasattr(args, f"{b}_file"), ["payload", "regex"]):
            setattr(args, f"{a}_file", None)

    s = None

    if args.script_type == "active":
        default = {"only_param": ".*", "time_between_requests": 500}

        for k, v in default.items():
            setattr(args, k, getattr(args, k, default[k]))

        s = ActiveScript(description=args.script_description)
        s.params = {
            "onlyParamNameRegExp": args.only_param,
            "appendPayloadToParam": args.append_payload,
            "timeBetweenRequests": args.time_between_requests,
            "payloads": file_lines_or_default(args.payload_file, args.payload),
        }

    elif args.script_type == "passive":
        s = PassiveScript(description=args.script_description)

    if s:  # Active and passive scripts
        finding = Finding(
            name=args.finding_title,
            description=args.finding_description,
            risk=args.finding_risk,
            confidence=args.finding_confidence,
        )

        s.params.update(
            {
                "finding": finding.__dict__,
                "searchIn": args.search_in,
                "regexp": file_lines_or_default(args.regex_file, args.regex),
            }
        )

    zap_options = {}

    if args.rapidast_config:
        try:
            rapidast_config = yaml.safe_load(args.rapidast_config)
        except yaml.YAMLError as e:
            raise RuntimeError(
                "Something went wrong parsing the {} file: {}".format(
                    args.rapidast_config.name, str(e)
                )
            )
        zap_options["proxies"] = rapidast_config["general"]["localProxy"]
        zap_options["apikey"] = rapidast_config["general"]["apiKey"]

    if args.delete_existing:
        logger.info("Deleting previously generated scripts")
        delete_all_loaded_scripts(**zap_options)

    if s and args.output:
        print(s.code, file=args.output)

    if s and args.load_and_enable:
        logger.info("Loading the script to ZAP")
        add_and_load_script(s, **zap_options)
