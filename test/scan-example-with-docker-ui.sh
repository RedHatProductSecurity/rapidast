#### 
# This script is to test a scan using docker-compose
#
# 1. Get a URL for the OAS3 definition file
# 2. Get a URL for the target API
# 3. Create config.yaml with the URLs and place it in config/
# 4. zaproxy_ui container must be running 
# $ docker-compose up zaproxy_ui
# 
# Run in the project root directory,
# $ test/scan-example-with-docker-ui.sh <dir_to_store_results>
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

# Load custom rules
docker-compose exec zaproxy_ui python scripts/gen_zap_script/cli.py --rapidast-config=./config/config.yaml --delete
docker-compose exec zaproxy_ui python scripts/gen_zap_script/cli.py --rapidast-config=./config/config.yaml --from-yaml scripts/gen_zap_script/rules/software_version_revealed.yaml --load-and-enable

# Run scan
docker-compose exec zaproxy_ui python scripts/apis_scan.py $1
