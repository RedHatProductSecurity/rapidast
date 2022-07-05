#!/bin/bash

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

sleep 30 # add a little more room until the instance is completely up

#python scripts/gen_zap_script/cli.py --delete
#python scripts/gen_zap_script/cli.py --from-yaml scripts/gen_zap_script/rules/software_version_revealed.yaml --load-and-enable


# Run scan
python scripts/apis_scan.py $1
