#!/usr/bin/env python3
#
# Extract the version of an artifact listed in artifacts.lock.yaml from its download URL.
#
# pylint: disable=C0103
import argparse
import sys
from urllib.parse import urlparse

import yaml


def version_from_github(url):
    # .../releases/download/v<version>/...
    parts = urlparse(url).path.split("/")
    tag = parts[parts.index("download") + 1]
    return tag.lstrip("v")


def version_from_k8s(url):
    # .../release/v<version>/...
    parts = urlparse(url).path.split("/")
    tag = parts[parts.index("release") + 1]
    return tag.lstrip("v")


def version_from_mozilla(url):
    # .../firefox/releases/<version>/...
    parts = urlparse(url).path.split("/")
    return parts[parts.index("releases") + 1]


VERSION_EXTRACTORS = {
    "github.com": version_from_github,
    "dl.k8s.io": version_from_k8s,
    "releases.mozilla.org": version_from_mozilla,
}


def main():
    parser = argparse.ArgumentParser(description="Extract artifact version from a lock file.")
    parser.add_argument("-a", required=True, help="Path to the artifacts.lock.yaml file")
    parser.add_argument("filename", help="Filename of the artifact")
    args = parser.parse_args()

    with open(args.a, encoding="utf-8") as f:
        data = yaml.safe_load(f)

    artifacts = data.get("artifacts", [])
    if not artifacts:
        print("No artifacts found in the file.", file=sys.stderr)
        sys.exit(1)

    artifact = next((a for a in artifacts if a["filename"] == args.filename), None)
    if artifact is None:
        print(f"Error: artifact '{args.filename}' not found in {args.a}", file=sys.stderr)
        sys.exit(1)

    download_url = artifact["download_url"]
    hostname = urlparse(download_url).hostname

    extractor = VERSION_EXTRACTORS.get(hostname)
    if extractor is None:
        print(f"Error: no version extractor for host '{hostname}'", file=sys.stderr)
        sys.exit(1)

    print(extractor(download_url))


if __name__ == "__main__":
    main()
