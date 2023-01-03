#!/usr/bin/bash

## Functions

function show_help() {
    cat <<EOD
$0 [-w | -f <compose>] [-c <CMD> | -s] [-d] [-D 0-2] [-h]
Run RapiDAST in a podman using the "podman-compose" command.
Options:
    -c <command> 
        Command to pass to podman-compose (default: 'up' to start the container)

    -s  Stop the container. 
        This is a shortcut for '-c down'

    -d  Runs in detach mode
        The command will return, and podman will run in the background

    -w  Runs the WebUI. 
        Note: if you do, you will have to connect to it before being able to start a scan
        This is a shortcut for '-f podman-compose-ui.yml'

    -f <compose.yaml>
        Run another podman-compose file (default: podman-compose.yml)

    -D <0-2>
        Debug mode: verbose output

    -h  Show this help

Examples:
    Both commands will start in the background a RapiDAST server in "WebUI" mode, and exit:
$0 -wd
$0 -f podman-compose-ui.yml -d

    Both commands will stop the container
$0 -s
$0 -c down
EOD
    exit 0
}
function debug() {
    if [ $RAPIDAST_DEBUG -gt 0 ]; then
        echo -e "RAPIDAST_DEBUG: " $* >&2
    fi
}

# DEFAULT OPTIONS (using default assign in case user wants to override values)
: "${RAPIDAST_COMPOSE:=podman-compose.yml}"
: "${RAPIDAST_COMMAND:=up}"
: "${RAPIDAST_DEBUG:=0}"

# NOTE/HACK: $RAPIDAST_MOREOPTS is not initialized on purpose so that users can add their own options to podman-compose, e.g.:
# (there is no simple way to do this using 'getopts')
# RAPIDAST_MOREOPTS="--quiet-pull" ./start_server_in_podman.s -wd 


while getopts "hD:f:wdc:s" opt; do
    case $opt in
    D) 
        RAPIDAST_DEBUG="$(( OPTARG ))";;
    h) 
        show_help;;
    f) 
        RAPIDAST_COMPOSE="$OPTARG";;
    w) 
        RAPIDAST_COMPOSE="podman-compose-ui.yml";;
    d) 
        RAPIDAST_MOREOPTS="$RAPIDAST_MOREOPTS --detach";;
    c)
        RAPIDAST_COMMAND="$OPTARG";;
    s)
        RAPIDAST_COMMAND="down"

    esac
done
shift "$((OPTIND-1))"

if [ $RAPIDAST_DEBUG -ge 2 ]; then
    set -x
fi

# Checks/verifications, etc.
if ! which podman-compose 2> /dev/null; then
    echo "[ERROR] no 'podman-compose' in PATH. Exiting"
    exit 1
fi

if [ "$RAPIDAST_COMMAND" == "up" ]; then
    # This *must* correspond to the UID/GID of the `zap` user in the container. 
    # The user is created with the command `useradd`, and thus may change in the future but is not likely to happen
    runas_UID=1000
    runas_GID=1000

    # Source of the idea for the hack: 
    # https://github.com/containers/podman/blob/main/troubleshooting.md#39-podman-run-fails-with-error-unrecognized-namespace-mode-keep-iduid1000gid1000-passed

    # Get the size of the mapping allowed to the user
    # The following commands look into /etc/subuid & /etc/subgid for figure out the size of the user's subUID mapping
    # but podman has a building mechanism to make the calculation easier.
    subuidSize=$(( $(podman info --format "{{ range .Host.IDMappings.UIDMap }}+{{.Size }}{{end }}" ) - 1 ))
    subgidSize=$(( $(podman info --format "{{ range  .Host.IDMappings.GIDMap }}+{{.Size }}{{end }}" ) - 1 ))

    # UIDs remap such that current host user is mapped as $runas_UID inside the container, and identical for GID
    #
    # we use a default assign in case a user wants to pass additional run arguments by pre-assigning RAPIDAST_RUNARGS
    RAPIDAST_RUNARGS+=" --uidmap 0:1:$runas_UID  --uidmap $runas_UID:0:1  --uidmap $(($runas_UID+1)):$(($runas_UID+1)):$(($subuidSize-$runas_UID))"
    RAPIDAST_RUNARGS+=" --gidmap 0:1:$runas_GID  --gidmap $runas_GID:0:1  --gidmap $(($runas_GID+1)):$(($runas_GID+1)):$(($subgidSize-$runas_GID))"
    RAPIDAST_RUNARGS="--podman-run-args=$RAPIDAST_RUNARGS"

fi

podman-compose -f "$RAPIDAST_COMPOSE" ${RAPIDAST_RUNARGS:+"$RAPIDAST_RUNARGS"} "$RAPIDAST_COMMAND" $RAPIDAST_MOREOPTS
