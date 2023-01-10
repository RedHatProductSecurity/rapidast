#!/bin/bash

##
## This file is used when the RapiDAST image is built with Containerfile as entrypoint
##

# This MUST be the same as resultDir in config.yaml
RESULT_DIR=results

# Create rundir
RUNDIR=$RESULT_DIR/$1
mkdir $RUNDIR

# Run in backgound to make sure we move on to following instructions
zap.sh -daemon -port 8090 -config api.key=$API_KEY -config database.newsession=3 -config database.newsessionprompt=false -addoninstall ascanrulesBeta &

# sleep to give ZAP a chance to get set up
while curl localhost:8090 >>/dev/null 2>&1; [ $? -ne 0 ]; do
  echo "[entrypoint] Waiting another 30s until ZAP is running up"
  sleep 30
done

echo "[entrypoint] Scanning will be starting soon in a min"
sleep 60 # add a little more room until the instance is completely up

# Run scan
python scripts/apis_scan.py $1
