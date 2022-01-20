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
mkdir $RUNDIR
podman unshare chown 1000 $RUNDIR

# Load custom rules
podman exec zaproxy  python scripts/gen-zap-script/cli.py --api-key=cnmeemn7jp7ijd8rl5u14q40v8 --delete
podman exec zaproxy python scripts/gen-zap-script/cli.py --from-yaml scripts/gen-zap-script/rules/software_version_revealed.yaml --api-key=cnmeemn7jp7ijd8rl5u14q40v8 --load-and-enable

# Run scan
podman exec zaproxy python scripts/apis_scan.py $1
