#!/usr/bin/env python3
#######################################
#
# [v0.1.1] OOBT(Out of Band testing) for Kubernetes.
# This is to detect vulnerabilites that can be detected with OOBT such as blind command injection.
#
# Current internal workflow:
#  1. run a callback server
#  2. apply k8s config (via '-f'), modifying the value of each of the 'spec' parameters, with a 'curl' command for POC
#  3. check if a connection was requested to the server
#  4. print a result message
#
# A usage example (see options in the code):
#  $ python3 oobtkube.py -d <timeout> -p <port> -i <ipaddr> -f <your_cr_config_example>.yaml
#
#
# Changelog:
#
#  - 0.1.1: add INFO logs to show test progress (key name, counts, vulnerability found)
#  - 0.1.0: produce SARIF result and improvements
#  - 0.0.1: init
# Roadmap:
#  - more payload
#  - improve modulization and extensibility
#
# Author: jechoi@redhat.com
#
######################################
import argparse
import copy
import json
import logging
import os
import queue
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
from typing import Dict
from typing import Generator
from typing import List
from typing import Optional
from typing import Union

import yaml

SERVER_HOST = "0.0.0.0"
MESSAGE_DETECTED = "OOB REQUEST DETECTED!!"
MESSAGE_NOT_DETECTED = "No OOB request detected"


class SarifConverter:
    TOOL_NAME = "RapiDAST-oobtkube"
    TOOL_VERSION = "0.1.0"

    base_sarif_output = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": TOOL_NAME, "version": TOOL_VERSION}},
                "results": [],
            }
        ],
    }

    def convert_to_sarif_json(self, result_message, artifact_url="", snippet=""):
        sarif_output = self.base_sarif_output
        sarif_output["runs"][0]["results"] = [
            {
                "level": "error",
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": artifact_url},
                            "region": {
                                "startLine": 1,
                                "properties": {
                                    # pylint: disable=C0301
                                    "startLineFailure": "Resolved invalid start line: 0 - used fallback value instead."
                                },
                                "snippet": {"text": snippet},
                            },
                        }
                    }
                ],
                "message": {"text": result_message},
                "ruleId": "RAPIDAST-OOBTKUBE-00001",
            }
        ]

        return json.dumps(sarif_output)

    def get_no_result_sarif(self):
        return json.dumps(self.base_sarif_output)


def get_sarif_output(shared_queue):
    result_message = f"{MESSAGE_DETECTED}"

    kubernetes_api_url = get_kubernetes_api_url()
    if kubernetes_api_url:
        logging.debug(f"Kubernetes API URL: {kubernetes_api_url}")
        artifact_url = kubernetes_api_url
    else:
        logging.error("Failed to retrieve Kubernetes API URL.")
        artifact_url = "a target k8s operator"

    snippet = "\n".join(get_all_items_in_queue(shared_queue))
    logging.info(f"Request received: {snippet}")

    sarif_conv = SarifConverter()

    return sarif_conv.convert_to_sarif_json(result_message, artifact_url, snippet)


def test_payload(filename: str):
    redirect = "&> /dev/null"
    if logging.getLogger().isEnabledFor(logging.DEBUG):
        # don't supress output when debug logging
        redirect = ""
    # if using 'apply' and a resource already exists, the command won't run as it returns as 'unchanged'
    # therefore 'create' and 'replace' are used
    kube_cmd = f"kubectl create -f {filename} {redirect} || kubectl replace -f {filename} {redirect}"

    logging.debug(f"Command run: {kube_cmd}")
    exit_code = os.system(kube_cmd)
    if exit_code == 0:
        # if object create/update succeeds add a small delay to allow
        # for a possible command injection to occur, before replacing
        # the object again with another command injection attempt
        time.sleep(1)


def find_leaf_keys_and_test(data: Dict, ipaddr: str, port: int) -> int:
    """
    Iterate the object data and test each leaf key by modifying the value with the attack payload.
    Test cases: appending 'curl' command, TBD
    """

    def get_leaf_keys(obj: Union[Dict, List], path: Optional[List] = None) -> Generator[List[str], None, None]:
        """Collect all possible leaves in the k8s object"""
        if isinstance(obj, dict):
            items = obj.items()
        elif isinstance(obj, list):
            items = enumerate(obj)
        else:
            return

        if path is None:  # avoids W0102: Dangerous default value [] as argument (dangerous-default-value)
            path = []

        for key, value in items:
            # skip modifying these top-level keys, we mostly want to test 'spec' data of k8s API objects
            if path == [] and key in ("apiVersion", "kind", "metadata"):
                continue

            current_path = path + [key]

            if isinstance(value, (dict, list)):
                yield from get_leaf_keys(value, current_path)
            else:
                yield current_path

    def modify_leaf_key(obj: Union[Dict, List], path: List, value: str) -> Union[Dict, List]:
        """Create a new object with a single modified value at the given path"""
        new_obj = copy.deepcopy(obj)
        current = new_obj

        # Navigate to the parent of the target node
        for key in path[:-1]:
            current = current[key]

        current[path[-1]] = value

        return new_obj

    leaf_keys = list(get_leaf_keys(data))

    # For each leaf key, create a new modified object with an injected payload
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml") as tmp:
        for i, path in enumerate(leaf_keys):
            path_str = ".".join(str(p) for p in path)
            logging.info(f"Testing leaf key ({i+1} / {len(leaf_keys)}): {path_str}")
            # TODO test more kinds of payload variations
            payload = f"echo oobt; curl {ipaddr}:{port}/{path_str}"
            modified_data = modify_leaf_key(data, path, payload)

            yaml.dump(modified_data, tmp)
            test_payload(tmp.name)

    return len(leaf_keys)


def parse_obj_data(filename: str) -> dict:
    with open(filename, "r", encoding="utf-8") as file:
        try:
            return yaml.safe_load(file)
        except yaml.YAMLError as e:
            logging.error(f"Error parsing YAML: {e}")
    return {}


def start_socket_listener(port, shared_queue, data_received, stop_event, duration):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server_socket.bind((SERVER_HOST, port))
    except OSError as e:
        logging.error(f"{e}. Stopping the server. It might take a few seconds. Please try again later.")
        stop_event.set()
        server_socket.close()
        return
    server_socket.settimeout(duration)
    server_socket.listen(1)

    logging.info(f"Listening on port {port}")

    client_socket = None
    try:
        client_socket, client_address = server_socket.accept()
        logging.info(f"Accepted connection from {client_address}")

        while not stop_event.is_set():
            data = client_socket.recv(1024)
            if not data:
                break

            shared_queue.put(data.decode("utf-8"))

            # Send a custom response back to the client
            response = "HTTP/1.1 200 OK\r\n\r\nfrom oob_listener!\n"
            client_socket.send(response.encode("utf-8"))

            data_received.set()

            break

    except socket.timeout:
        logging.info("Socket timeout reached as the test duration expired. Stopping the server.")

    except Exception as e:
        raise RuntimeError("An error occurred. See logs for details.") from e

    finally:
        if client_socket:
            client_socket.close()
        if server_socket:
            server_socket.close()


def get_kubernetes_api_url():
    try:
        # Run kubectl cluster-info command and capture the output
        output = subprocess.check_output(["kubectl", "cluster-info"]).decode("utf-8")

        # Find the line containing the Kubernetes master URL
        lines = output.split("\n")
        for line in lines:
            if "is running at" in line:
                # Use regular expression to extract the URL
                url_match = re.search(r"(https?://[^\s;]+:[0-9]+)", line)

                if url_match:
                    # Extract and print the URL
                    api_url = url_match.group(1)
                    logging.debug(f"Kubernetes API server URL: {api_url}")
                    return api_url
        # Return None if URL is not found
        return None
    except subprocess.CalledProcessError as e:
        # Handle error if kubectl command fails
        logging.error(f"Error: {e}")
        return None


def get_all_items_in_queue(q):
    items = []
    while not q.empty():
        items.append(q.get())
    return items


def print_result(sarif_output, file_output=False, message_detected=False):
    if file_output:
        with open(file_output, "w", encoding="utf-8") as f:
            f.write(sarif_output)
    else:
        if message_detected:
            logging.info(f"OOBTKUBE RESULT: {MESSAGE_DETECTED}")
        else:
            logging.info(f"OOBTKUBE RESULT: {MESSAGE_NOT_DETECTED}")

        logging.info(sarif_output)


def check_can_create(obj_data: dict) -> bool:
    """Check if possible to create target resources. Verifies connection, sufficient permissions etc"""
    resource = obj_data["kind"]  # kind must always be present in resource file
    try:
        subprocess.run(["kubectl", "auth", "can-i", "create", resource], check=True, capture_output=True, timeout=30)
    except subprocess.TimeoutExpired as e:
        logging.error(e)
        return False
    except subprocess.CalledProcessError as e:
        err = e.stderr.decode().rstrip()
        logging.error(f"Unable to create {resource} resource(s): {err}")
        return False
    return True


# pylint: disable=R0915
def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Simulate a socket listener and respond to requests.")
    parser.add_argument(
        "-i",
        "--ip-addr",
        type=str,
        required=True,
        help="Public IP address for the test target to access",
    )
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=12345,
        help="Port number for the socket listener (default: 12345)",
    )
    parser.add_argument(
        "-d",
        "--duration",
        type=int,
        default=300,
        help="Duration for the listener thread to run in seconds (default: 300 seconds)",
    )
    parser.add_argument("-f", "--filename", type=str, required=True, help="Kubernetes config file path")
    # add argument for '-o' to output the result to a file
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        help="Output result to a file in the SARIF format (default: stdout)",
    )
    parser.add_argument(
        "--find-all",
        action="store_true",
        help="Test all the parameters even if one is found vulnerable",
    )
    parser.add_argument(
        "--log-level",
        dest="loglevel",
        choices=["debug", "info", "warning", "error"],
        default="info",
        help="Level of verbosity",
    )

    args = parser.parse_args()
    args.loglevel = args.loglevel.upper()

    logging.basicConfig(format="%(levelname)s: %(message)s", level=args.loglevel)

    if not args.filename:
        logging.error("Error: Please provide a filename using the --filename option.")
        sys.exit(1)

    # Check if the file exists before creating a thread
    if not os.path.exists(args.filename):
        raise FileNotFoundError(f"The file '{args.filename}' does not exist.")

    # if we can't parse the resource file, or lack permission to create such
    # resources, then exit early
    obj_data = parse_obj_data(args.filename)
    if not obj_data or not check_can_create(obj_data):
        sys.exit(1)

    # Init variables
    data_has_been_received = False
    shared_queue = queue.Queue()

    # Create a few threading events
    data_received = threading.Event()
    stop_event = threading.Event()

    # Start socket listener in a separate thread
    socket_listener_thread = threading.Thread(
        target=start_socket_listener,
        args=(args.port, shared_queue, data_received, stop_event, args.duration),
    )
    socket_listener_thread.start()

    logging.info(f"OOBTKUBE test started, with duration set to {args.duration} seconds")

    # Wait for a while to ensure the socket listener is up
    # You may need to adjust this delay based on your system
    time.sleep(5)

    if stop_event.is_set():
        logging.error("Socket listener failed to start. Exiting...")
        sys.exit(1)

    logging.debug("Listener thread started")

    # Record the start time for the main function
    start_time_main = time.time()
    elapsed_time_main = 0

    # Run kubectl apply command
    find_leaf_keys_and_test(obj_data, args.ip_addr, args.port)

    # Check the overall duration periodically
    vulnerability_count = 0
    while not stop_event.is_set():
        time.sleep(1)  # Adjust the sleep duration as needed
        elapsed_time_main = time.time() - start_time_main
        if elapsed_time_main >= args.duration:
            logging.debug(f"The duration of {args.duration} seconds has reached. Exiting...")
            stop_event.set()

        if data_received.is_set():
            sarif_output = get_sarif_output(shared_queue)

            print_result(sarif_output, args.output, True)

            vulnerability_count += 1
            logging.info(f"A vulnerability has been found. Total: {vulnerability_count}")

            data_has_been_received = True

            if args.find_all:
                data_received.clear()
            else:
                stop_event.set()
                break

    # Wait for the socket listener thread to finish or timeout
    socket_listener_thread.join()

    if not data_has_been_received:
        sarif_converter = SarifConverter()
        print_result(sarif_converter.get_no_result_sarif(), args.output, False)

    logging.info(f"The test ran for {elapsed_time_main} seconds.")
    sys.exit(0)


if __name__ == "__main__":
    main()
