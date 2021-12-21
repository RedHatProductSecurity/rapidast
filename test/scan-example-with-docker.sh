#### 
# This script is to test a scan using docker-compose
#
# 1. Get a URL for the OAS3 definition file
# 2. Get a URL for the target API
# 3. Create config.yaml with the URLs and place it in config/
# 4. zaproxy container must be running 
# $ docker-compose up zaproxy
# 
# Run in the project root directory,
# $ test/scan-example-with-docker.sh <dir_to_store_results>
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
docker-compose exec zaproxy python scripts/gen-zap-script/cli.py --api-key=cnmeemn7jp7ijd8rl5u14q40v8 --delete
docker-compose exec zaproxy python scripts/gen-zap-script/cli.py --from-yaml scripts/gen-zap-script/rules/software_version_revealed.yaml --api-key=cnmeemn7jp7ijd8rl5u14q40v8 --load-and-enable

# Run scan
docker-compose exec zaproxy python scripts/apis_scan.py $1
