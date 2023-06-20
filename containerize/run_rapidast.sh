#!/usr/bin/bash

CONF=$(realpath $1)

pushd /opt/rapidast/
./rapidast.py --log-level debug --config "${CONF}"
