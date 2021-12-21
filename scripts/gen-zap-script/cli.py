import argparse
import itertools
import json
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
logger = logging.Logger('GenZAPScriptMain')
logger.addHandler(logging.StreamHandler())


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Generate active and passive ZAP scripts')
    parser.add_argument('--delete-existing', action='store_true', help='Delete previously generated ZAP scripts (active+passive)')
    parser.add_argument('--load-and-enable', action='store_true', help='Load and enable the generated ZAP script (if --delete-existing is specified it is executed first')
    parser.add_argument('--output', type=argparse.FileType('w'), default=None, help='Output file for generated ZAP script, default is not displayed')
    parser.add_argument('--script-description', type=str, default='Empty description', help='Script description in ZAP')
    parser.add_argument('--debug', action='store_true', help='Print debug messages')
    parser.add_argument('--api-key', type=str, default='', help='ZAP API key, used for --delete-existing and --load-and-enable')
    parser.add_argument('--from-yaml', type=argparse.FileType('r'), help='Import script definition from a YAML file')

    ## Finding
    def add_finding_group(parser):
        findingGroup = parser.add_argument_group(title='Finding definition')
        findingGroup.add_argument('--finding-title', type=str, required=True)
        findingGroup.add_argument('--finding-description', type=str, default='')
        findingGroup.add_argument('--finding-confidence', type=int, choices=list(range(1, 4)), default=1)
        findingGroup.add_argument('--finding-risk', type=int, choices=list(range(0, 4)), default=1)

    # Active or Passive
    scriptType = parser.add_subparsers(title='Script type', dest='script_type')

    # Active
    scriptTypeActive = scriptType.add_parser('active', help='Script for ZAP active scanner')
    add_finding_group(scriptTypeActive)
    ## Payloads
    payloadsGroup = scriptTypeActive.add_argument_group(title='Payloads definition', description='Payloads are literals inserted or appended to URL/body parameters scanned by ZAP.')
    payloadDefinitionGroup = payloadsGroup.add_mutually_exclusive_group(required=True)
    payloadDefinitionGroup.add_argument('--payload', type=str, nargs='+', help='Payload(s) to insert/append to the scanned parameter')
    payloadDefinitionGroup.add_argument('--payload-file', type=argparse.FileType('r'), help='Payloads file, one per line, to insert/append to the scanned parameter')
    ### Payload insertion options
    payloadsGroup.add_argument('--only-param', type=str, help='Only try payloads for parameters matching this regexp (default is all parameters)', default='.*')
    payloadsGroup.add_argument('--append-payload', default=False, action='store_true', help='Append Payloads to the parameter')

    def msCheck(x):
        try:
            x = int(x)
            if x < 0:
                raise ValueError()
        except ValueError:
            raise argparse.ArgumentTypeError('Positive integer expected for milliseconds count')
        return x

    payloadsGroup.add_argument('--time-between-requests', type=msCheck, default=500, help='Time between requests, in milliseconds')
    ## Response processing
    responseProcessingGroup = scriptTypeActive.add_argument_group(title='Response processing', description='Process responses to injected parameters')
    searchInChoices = ['response.header', 'response.body']
    responseProcessingGroup.add_argument('--search-in', choices=searchInChoices, required=True, default='response.body', help='Where should the regexp be matched')
    regexpGroup = responseProcessingGroup.add_mutually_exclusive_group(required=True)
    regexpGroup.add_argument('--regex', type=str, nargs='+', help='Regular Expression to evaluate')
    regexpGroup.add_argument('--regex-file', type=str, help='Regular Expressions to evaluate, one per line')

    # Passive
    scriptTypePassive = scriptType.add_parser('passive', help='Script for ZAP passive scanner for HTTP requests or responses')
    add_finding_group(scriptTypePassive)
    ## Request/Response search definition
    searchGroup = scriptTypePassive.add_argument_group(title='Search definition')
    searchInChoices = ['request.method', 'request.url'] + ['.'.join(a) for a in itertools.product(*[['request', 'response'], ['header', 'body']])]
    searchGroup.add_argument('--search-in', choices=searchInChoices, required=True, default='response.body', help='Where should the regexp be matched')
    regexpGroup = searchGroup.add_mutually_exclusive_group(required=True)
    regexpGroup.add_argument('--regex', type=str, nargs='+', help='Regular Expression to evaluate')
    regexpGroup.add_argument('--regex-file', type=str, help='Regular Expressions to evaluate, one per line')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
    else:
        args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)

    def file_lines_or_default(filefp, default):
        return ([x.rstrip() for x in filefp.readlines()] if filefp else default) or list()

    if args.from_yaml:
        yamlConf = yaml.safe_load(args.from_yaml)
        delattr(args, 'from_yaml')

        for k, v in yamlConf.items():
            if isinstance(v, list):
                if not hasattr(args, k):
                    setattr(args, k, list())
                for val in v:
                    getattr(args, k).append(val)
            else:
                setattr(args, k, v)

        # Because yaml import don't require active/passive sub-parser to execute, we need some fixtures
        for a in filter(lambda b: not hasattr(args, f'{b}_file'), ['payload', 'regex']):
            setattr(args, f'{a}_file', None)

    s = None

    if args.script_type == 'active':
        default = {'only_param': '.*', 'time_between_requests': 500}

        for k, v in default.items():
            setattr(args, k, getattr(args, k, default[k]))

        s = ActiveScript(description=args.script_description)
        s.params = {
            'onlyParamNameRegExp': args.only_param,
            'appendPayloadToParam': args.append_payload,
            'timeBetweenRequests': args.time_between_requests,
            'payloads': file_lines_or_default(args.payload_file, args.payload),
        }

    elif args.script_type == 'passive':
        s = PassiveScript(description=args.script_description)

    if s:   # Active and passive scripts
        finding = Finding(name=args.finding_title, description=args.finding_description, risk=args.finding_risk,
                          confidence=args.finding_confidence)

        s.params.update({
            'finding': finding.__dict__,
            'searchIn': args.search_in,
            'regexp': file_lines_or_default(args.regex_file, args.regex)
        })

    # Zap options, proxies are plucked from environment
    zapOptions = {
        #'proxies': {k.split('_')[0].lower(): os.environ.get(k) for k in ['HTTP_PROXY', 'HTTPS_PROXY', 'http_proxy', 'https_proxy'] if os.environ.get(k)},
        'proxies': {'http': 'http://127.0.0.1:8090', 'https': 'http://127.0.0.1:8090'},
        'apikey': args.api_key
    }

    if args.delete_existing:
        logger.info('Deleting previously generated scripts')
        delete_all_loaded_scripts(**zapOptions)

    if s and args.output:
        print(s.code, file=args.output)

    if s and args.load_and_enable:
        logger.info('Loading the script to ZAP')
        add_and_load_script(s, **zapOptions)
