echo "DEPRECATED. use ./podman-wrapper.sh"
podman-compose -f podman-compose.yml down
podman-compose -f podman-compose-ui.yml down
podman-compose -f podman-compose-ui.yml up
