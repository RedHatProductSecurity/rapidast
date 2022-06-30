#!/bin/bash

# This MUST be the same as resultDir in config.yaml
RESULT_DIR=results

# Create rundir
RUNDIR=$RESULT_DIR/$1
mkdir $RUNDIR


# Run in backgound to make sure we move on to following instructions
zap.sh -cmd -addonupdate && zap.sh -daemon -port 8090 -config api.key=$API_KEY -config database.newsession=3 -config database.newsessionprompt=false -addoninstall ascanrulesBeta &

# sleep to give ZAP a chance to get set up
sleep 45

python scripts/gen_zap_script/cli.py --rapidast-config=./config/config.yaml --delete
python scripts/gen_zap_script/cli.py --rapidast-config=./config/config.yaml --from-yaml scripts/gen_zap_script/rules/software_version_revealed.yaml --load-and-enable


# Run scan
python scripts/apis_scan.py $1
