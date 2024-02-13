#!/usr/bin/env python3
#######################################
#
# [POC v0.0.1] OOBT(Out of Band testing) for Kubernetes.
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
# Roadmap:
#  - improve logging
#  - more payload
#  - improve modulization and extensibility
#
# Author: jechoi@redhat.com
#
######################################
import argparse
import json
import os
import queue
import re
import socket
import subprocess
import sys
import threading
import time

import yaml

SERVER_HOST = "0.0.0.0"
MESSAGE_DETECTED = "OOB REQUEST DETECTED!!"
MESSAGE_NOT_DETECTED = "No OOB request detected"


def get_spec_from_yaml(yaml_file):
    with open(yaml_file, "r", encoding="utf-8") as file:
        data = yaml.safe_load(file)

        spec = data.get(
            "spec", {}
        )  # If 'spec' key is not present, return an empty dictionary
        return spec


def scan_with_k8s_config(cfg_file_path, ipaddr, port):
    # Apply Kubernetes config (e.g. CR for Operator, or Pod/resource for webhook)
    tmp_file = "/tmp/oobtkube-test.yaml"

    spec = get_spec_from_yaml(cfg_file_path)
    if not spec:
        # pylint: disable=W0719
        raise Exception("no spec found")

    # test each spec
    for sitem in spec.keys():
        cmd = f"sed 's/{sitem}:.*/{sitem}: \"curl {ipaddr}:{port}\\/{sitem}\"/g' {cfg_file_path} > {tmp_file}"
        print(f"Command run: {cmd}")
        os.system(cmd)

        # if using 'apply' and a resource already exists, the command won't run as it returns as 'unchanged'
        # therefore 'create' and 'replace' are used
        kube_cmd = f"kubectl create -f {tmp_file} > /dev/null 2>&1; kubectl replace -f {tmp_file}"

        print(f"Command run: {kube_cmd}")
        os.system(kube_cmd)


def start_socket_listener(port, shared_queue, data_received, stop_event, duration):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server_socket.bind((SERVER_HOST, port))
    except OSError as e:
        print(
            f"{e}. Stopping the server. It might take a few seconds. Please try again later."
        )
        stop_event.set()
        server_socket.close()
        return
    server_socket.settimeout(duration)
    server_socket.listen(1)

    print(f"Listening on port {port}")

    try:
        client_socket = None
        client_socket, client_address = server_socket.accept()
        print(f"Accepted connection from {client_address}")

        while not stop_event.is_set():
            data = client_socket.recv(1024)
            if not data:
                break

            shared_queue.put(data.decode("utf-8"))

            # Send a custom response back to the client
            response = "HTTP/1.1 200 OK\r\n\r\nfrom oob_listener!\n"
            client_socket.send(response.encode("utf-8"))

            data_received.set()

            # Stop the listener after the first request
            stop_event.set()
            break

    except TimeoutError:
        print("Timeout reached. Stopping the server.")
        pass

    except Exception as e:
        raise RuntimeError("An error occurred. See logs for details.") from e

    finally:
        if client_socket:
            client_socket.close()
        if server_socket:
            server_socket.close()


def convert_to_sarif_json(result_message, tool_name, artifact_url="", snippet=""):
    sarif_output = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": tool_name, "version": "1.0.0"}},
                "results": [
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
                ],
            }
        ],
    }
    return json.dumps(sarif_output)


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
                    print("Kubernetes API server URL:", api_url)
                    return api_url
        # Return None if URL is not found
        return None
    except subprocess.CalledProcessError as e:
        # Handle error if kubectl command fails
        print("Error:", e)
        return None


# pylint: disable=R0915
def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(
        description="Simulate a socket listener and respond to requests."
    )
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
    parser.add_argument(
        "-f", "--filename", type=str, required=True, help="Kubernetes config file path"
    )
    # add argument for '-o' to output the result to a file
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        help="Output result to a file in the SARIF format (default: stdout)",
    )

    args = parser.parse_args()

    if not args.filename:
        print("Error: Please provide a filename using the --filename option.")
        sys.exit(1)

    # Check if the file exists before creating a thread
    if not os.path.exists(args.filename):
        raise FileNotFoundError(f"The file '{args.filename}' does not exist.")

    # Create a few threading events
    data_received = threading.Event()
    stop_event = threading.Event()
    shared_queue = queue.Queue()

    # Start socket listener in a separate thread
    socket_listener_thread = threading.Thread(
        target=start_socket_listener,
        args=(args.port, shared_queue, data_received, stop_event, args.duration),
    )
    socket_listener_thread.start()

    # Wait for a while to ensure the socket listener is up
    # You may need to adjust this delay based on your system
    time.sleep(5)

    if stop_event.is_set():
        print("Socket listener failed to start. Exiting...")
        sys.exit(1)

    print("Listener thread started")

    # Record the start time for the main function
    start_time_main = time.time()

    # Run kubectl apply command
    scan_with_k8s_config(args.filename, args.ip_addr, args.port)

    # Check the overall duration periodically
    while not stop_event.is_set():
        time.sleep(1)  # Adjust the sleep duration as needed
        elapsed_time_main = time.time() - start_time_main
        if elapsed_time_main >= args.duration:
            print(f"Program running for {elapsed_time_main} seconds. Exiting...")
            stop_event.set()

    # Wait for the socket listener thread to finish or timeout
    socket_listener_thread.join()

    if data_received.is_set():
        result_message = f"{MESSAGE_DETECTED}"
        tool = "RapiDAST-oobtkube"

        kubernetes_api_url = get_kubernetes_api_url()
        if kubernetes_api_url:
            print("Kubernetes API URL:", kubernetes_api_url)
            artifact_url = kubernetes_api_url
        else:
            print("Failed to retrieve Kubernetes API URL.")
            artifact_url = "a target k8s operator"

        snippet = shared_queue.get()
        print("Request received:", snippet)

        sarif_output = convert_to_sarif_json(
            result_message, tool, artifact_url, snippet
        )

        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(sarif_output)
        else:
            print(f"OOBTKUBE RESULT: {MESSAGE_DETECTED}")
            print(sarif_output)
    else:
        print(f"OOBTKUBE RESULT: {MESSAGE_NOT_DETECTED}")
        sys.exit(0)


if __name__ == "__main__":
    main()
