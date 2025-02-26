#!/bin/bash -e

if [ -f "/cachi2/cachi2.env" ]; then
    echo "Sourcing Cachi2 environment"
    source /cachi2/cachi2.env

    # Python 3.12 doesn't include setuptools and wheel by default in 'ensurepip',
    # so we manually install them to make them available for building
    # prefetched dependencies
    PIP_NO_INDEX=  pip3 download setuptools wheel --dest "$PIP_FIND_LINKS"
fi
