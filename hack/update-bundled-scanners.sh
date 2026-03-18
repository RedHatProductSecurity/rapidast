#!/bin/bash
#
# Update scanners and other tools bundled in the RapiDAST container.
#
# GitHub CLI tool gh required to get information about GitHub releases.


# check for the latest ZAP version
update_zap() {
	varname="ZAP_VERSION"

	new_release=`gh release -R zaproxy/zaproxy ls --json name --jq '.[]|.name' \
		| grep -v '^w' \
		| head -n1`
	new_version="${new_release#v}"	# strip leading "v" from the release name

	if [ -z "$new_version" ]; then
		echo "ERROR: Failed to determine the latest ZAP version!" >&2
		return 1
	fi

	_is_update_needed "$varname" "$new_version" || return 0

	release_data=`gh release -R zaproxy/zaproxy view "$new_release" --json 'assets' \
			--jq ".assets[] | select(.name == \"ZAP_${new_version}_Linux.tar.gz\")"`

	url=`echo "$release_data" | jq -r '.url'`
	digest=`echo "$release_data" | jq -r '.digest'`

	_update_containerfiles "$varname" "$new_version"
	_update_artifacts 'ZAP.tar.gz' "$url" "$digest"

}


# check for the latest Firefox version
update_firefox() {
	varname="FF_VERSION"

	# see https://releases.mozilla.org/pub/firefox/releases/latest-esr/README.txt
	new_version=`curl -sS 'https://download.mozilla.org/?product=firefox-esr-latest&os=linux64&lang=en-US' \
		| grep -o 'firefox/releases/[0-9.]*esr/linux-x86_64' \
		| cut -d/ -f3`

	if [ -z "$new_version" ]; then
		echo "ERROR: Failed to determine the latest Firefox version!" >&2
		return 1
	fi

	_is_update_needed "$varname" "$new_version" || return 0

	ff_file="linux-x86_64/en-US/firefox-${new_version}.tar.xz"

	url="https://releases.mozilla.org/pub/firefox/releases/${new_version}/${ff_file}"
	digest=`curl -sS "https://releases.mozilla.org/pub/firefox/releases/${new_version}/SHA256SUMS" \
		| grep -F "$ff_file" \
		| awk '{ print $1 }'`

	_update_containerfiles "$varname" "$new_version"
	_update_artifacts 'firefox.tar.xz' "$url" "sha256:$digest"
}


# check for the latest Trivy version
update_trivy() {
	varname="TRIVY_VERSION"

	new_release=`gh release -R aquasecurity/trivy ls --json name --jq '.[]|.name' -L 1`
	new_version="${new_release#v}"	# strip leading "v" from the release name

	if [ -z "$new_version" ]; then
		echo "ERROR: Failed to determine the latest Trivy version!" >&2
		return 1
	fi

	_is_update_needed "$varname" "$new_version" || return 0

	release_data=`gh release -R aquasecurity/trivy view "$new_release" --json 'assets' \
			--jq ".assets[] | select(.name == \"trivy_${new_version}_Linux-64bit.tar.gz\")"`

	url=`echo "$release_data" | jq -r '.url'`
	digest=`echo "$release_data" | jq -r '.digest'`

	_update_containerfiles "$varname" "$new_version"
	_update_artifacts 'trivy.tar.gz' "$url" "$digest"
}


# check for the latest kubectl version
update_kubectl() {
	varname="K8S_VERSION"

	new_version=`curl -sS https://dl.k8s.io/release/stable.txt`
	new_version="${new_version#v}"	# strip leading "v"

	if [ -z "$new_version" ]; then
		echo "ERROR: Failed to determine the latest kubectl version!" >&2
		return 1
	fi

	_is_update_needed "$varname" "$new_version" || return 0

	url="https://dl.k8s.io/release/v$new_version/bin/linux/amd64/kubectl"
	digest=`curl -sSL "$url.sha256"`

	_update_containerfiles "$varname" "$new_version"
	_update_artifacts 'kubectl' "$url" "sha256:$digest"
}


# check if version update is needed
_is_update_needed() {
	local varname="$1"
	local new_version="$2"

	local current_version=`cat containerize/Containerfile \
		| grep "^ARG $varname=" \
		| cut -d= -f2`

	echo -n "$varname: $new_version "
	if [ "$new_version" == "$current_version" ]; then
		echo "- no update needed"
		return 1
	else
		echo "- updated needed from $current_version"
		return 0
	fi
}


# functions to update containerfiles and artifacts.lock.yaml
_update_containerfiles() {
	local varname="$1"
	local version="$2"

	sed -i -E "s/^(ARG $varname)=.*$/\\1=$version/" containerize/Containerfile containerize/Containerfile.garak
}

_update_artifacts() {
	local filename="$1"
	local url="$2"
	local digest="$3"

	filename="$filename" url="$url" digest="$digest" \
		yq -i '(.artifacts[] | select(.filename == env(filename)) )
			|= ( .download_url = env(url) | .checksum = env(digest) | .checksum style="double")' artifacts.lock.yaml
}


if [ ! -d containerize  -o  ! -f artifacts.lock.yaml ]; then
	echo "ERROR: This script must be run from the RapiDAST repository root directory!" >&2
	exit 1
fi

update_zap
update_firefox
update_trivy
update_kubectl
