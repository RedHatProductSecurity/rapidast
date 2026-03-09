#!/usr/bin/env python3
#
# Download artifacts listed in artifacts.lock.yaml and verify their checksums.
#
# pylint: disable=C0103
import argparse
import os
import subprocess
import sys
import tempfile

import yaml


def main():
    parser = argparse.ArgumentParser(description="Download and verify artifacts from a lock file.")
    parser.add_argument("-a", required=True, help="Path to the artifacts.lock.yaml file")
    parser.add_argument("-d", required=True, help="Destination directory for downloaded files")
    args = parser.parse_args()

    with open(args.a, encoding="utf-8") as f:
        data = yaml.safe_load(f)

    artifacts = data.get("artifacts", [])
    if not artifacts:
        print("No artifacts found in the file.", file=sys.stderr)
        sys.exit(1)

    os.makedirs(args.d, exist_ok=True)

    for artifact in artifacts:
        download_url = artifact["download_url"]
        filename = artifact["filename"]
        checksum = artifact["checksum"]
        dest_path = os.path.join(args.d, filename)

        if not checksum.startswith("sha256:"):
            print(f"Error: checksum for {filename} does not start with 'sha256:' prefix: {checksum}", file=sys.stderr)
            sys.exit(1)

        print(f"Downloading: {download_url}")
        result = subprocess.run(
            ["curl", "-sSfL", download_url, "-o", dest_path],
            check=False,
        )
        if result.returncode != 0:
            print(f"Error: artifact download failed (exit code {result.returncode})", file=sys.stderr)
            sys.exit(1)

        # Strip "sha256:" prefix from checksum
        expected_hash = checksum.removeprefix("sha256:")

        # Write a checksum file and verify with sha256sum
        with tempfile.NamedTemporaryFile(mode="w", suffix=".sha256", delete=False, dir=args.d) as chk:
            chk.write(f"{expected_hash}  {filename}\n")
            chk_path = chk.name

        try:
            print(f"Verifying checksum for {filename}: {checksum}")
            result = subprocess.run(
                ["sha256sum", "--check", "--quiet", chk_path],
                cwd=args.d,
                check=False,
            )
            if result.returncode != 0:
                print(f"Error: checksum verification failed for {filename}", file=sys.stderr)
                sys.exit(1)
        finally:
            os.unlink(chk_path)

    print("All artifacts downloaded and verified successfully.")


if __name__ == "__main__":
    main()
