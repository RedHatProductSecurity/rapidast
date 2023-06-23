#!/usr/bin/bash

# config file should be either absolute path or URL
CONF=$1

pushd /opt/rapidast/
./rapidast.py --config "${CONF}"
