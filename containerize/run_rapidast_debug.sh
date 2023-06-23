#!/usr/bin/bash

# in debug mode, only local config file can be used
CONF=$(realpath $1)

pushd /opt/rapidast/
./rapidast.py --log-level debug --config "${CONF}"
