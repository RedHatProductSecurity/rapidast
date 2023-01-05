#### 
# This script is to test a scan using podman
#
# 1. Get a URL for the OAS3 definition file
# 2. Get a URL for the target API
# 3. Create config.yaml with the URLs and place it in config/
# 4. zaproxy container must be running (either runenv.sh or runenv-ui.sh)
# 
# Run in the project root directory,
# $ test/scan-example-with-podman.sh <dir_to_store_results>
#
####

# This MUST be the same as resultDir in config.yaml
RESULT_DIR=results

# create dir
if [ -z "$1" ]
	then
		echo "No argument supplied"
		echo "Usage: $0 <dir_to_store_results>"
		exit
fi

# Create rundir
RUNDIR=$RESULT_DIR/$1
mkdir -p $RUNDIR

# Load custom rules
podman exec zaproxy python scripts/gen_zap_script/cli.py --rapidast-config=./config/config.yaml --delete
podman exec zaproxy python scripts/gen_zap_script/cli.py --rapidast-config=./config/config.yaml --from-yaml scripts/gen_zap_script/rules/software_version_revealed.yaml --load-and-enable

# Run scan
podman exec zaproxy python scripts/apis_scan.py $1
