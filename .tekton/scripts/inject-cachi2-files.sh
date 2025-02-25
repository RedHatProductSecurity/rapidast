#!/bin/bash -e

# The file cachi2/output/.build-config.json specifies where cachi2 expects to find
# the project sources. By default, Konflux points them to /var/workdir/source.
# Create a symbolic link from /workspace to /var/workdir/source

mkdir -p /var/workdir/
ln -s /workspace /var/workdir/source
echo "Symbolic link created: /workspace to /var/workdir/source"
cachi2 --log-level="debug" inject-files /cachi2/output
