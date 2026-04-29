#!/bin/bash
#
# Update scanners and other tools bundled in the RapiDAST container.
#
# GitHub CLI tool gh required to get information about GitHub releases.  jq,
# yq, and xq tools required to parse data and update artifacts file.


ARTIFACTS_FILE='artifacts.lock.yaml'
ARTIFACTS_TMPDIR='tmp-artifacts'


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


# check for the ZAP addon updates
update_zap_addons() {
	local ZAP_VERSION_SHORT
	ZAP_VERSION_SHORT=$(hack/get-artifact-version.py -a "$ARTIFACTS_FILE" 'ZAP.tar.gz' | cut -d. -f1,2)

	hack/download-artifacts.py -a "$ARTIFACTS_FILE" -d "$ARTIFACTS_TMPDIR" 'ZAP.tar.gz' || return 1

	local zapversions_xml="$ARTIFACTS_TMPDIR/ZapVersions-$ZAP_VERSION_SHORT.xml"
	curl -sSL -o "$zapversions_xml" \
		"https://github.com/zaproxy/zap-admin/raw/refs/heads/master/ZapVersions-$ZAP_VERSION_SHORT.xml"
	if [ ! -s "$zapversions_xml" ]; then
		echo "ERROR: Failed to download ZapVersions-$ZAP_VERSION_SHORT.xml" >&2
		return 1
	fi

	# Build a temp artifacts file with all .zap entries stripped; we'll add back
	# only the entries that reflect the latest versions from ZapVersions XML.
	local tmp_artifacts="${ARTIFACTS_FILE}.tmp"
	yq 'del(.artifacts[] | select(.filename | test("\.zap$")))' "$ARTIFACTS_FILE" > "$tmp_artifacts"

	for i in $(tar tf "$ARTIFACTS_TMPDIR/ZAP.tar.gz" '*.zap' | sed 's,^.*/,,') ; do
		local addon_name="${i%-*-*.zap}"
		local tmp="${i%.zap}"
		local current_status="${tmp#${addon_name}-}"; current_status="${current_status%-*}"
		local current_version="${tmp##*-}"

		local xml_version xml_status xml_file xml_url xml_hash

		xml_version=$(xq -x "/ZAP/addon_${addon_name}/version" "$zapversions_xml")
		if [ -z "$xml_version" ]; then
			echo "$addon_name: not found in ZapVersions XML, skipping" >&2
			continue
		fi

		xml_status=$(xq -x "/ZAP/addon_${addon_name}/status" "$zapversions_xml")
		if [ "$xml_status" != "$current_status" ]; then
			echo "$addon_name: status changed from $current_status to $xml_status, skipping"
			continue
		fi

		if [ "$xml_version" = "$current_version" ]; then
			echo "$addon_name: distribution=$current_version latest=$xml_version - no update needed"
			continue
		fi

		local artifacts_filename artifacts_version
		artifacts_filename=$(prefix="${addon_name}-${xml_status}-" \
			yq '.artifacts[] | select(.filename | test("^" + env(prefix))) | .filename' "$ARTIFACTS_FILE")
		artifacts_version="${artifacts_filename%.zap}"; artifacts_version="${artifacts_version##*-}"

		if [ "$xml_version" = "$artifacts_version" ]; then
			echo "$addon_name: distribution=$current_version latest=$xml_version artifacts=$artifacts_version - already updated"
		else
			echo "$addon_name: distribution=$current_version latest=$xml_version artifacts=${artifacts_version:-none} - update needed"
		fi

		xml_file=$(xq -x "/ZAP/addon_${addon_name}/file" "$zapversions_xml")
		xml_url=$(xq -x "/ZAP/addon_${addon_name}/url" "$zapversions_xml")
		xml_hash=$(xq -x "/ZAP/addon_${addon_name}/hash" "$zapversions_xml")
		if [[ "$xml_hash" != SHA-256:* ]]; then
			echo "$addon_name: unexpected hash format '$xml_hash', skipping" >&2
			continue
		fi
		xml_hash="sha256:${xml_hash#SHA-256:}"

		filename="$xml_file" url="$xml_url" digest="$xml_hash" \
			yq -i '.artifacts += [{"filename": env(filename), "download_url": env(url), "checksum": env(digest)}]
				| (.artifacts[-1].checksum) style="double"' \
			"$tmp_artifacts"
	done

	if ! diff -q "$ARTIFACTS_FILE" "$tmp_artifacts" > /dev/null 2>&1; then
		mv "$tmp_artifacts" "$ARTIFACTS_FILE"
		echo "artifacts.lock.yaml updated with new ZAP addon versions"
	else
		rm "$tmp_artifacts"
		echo "No ZAP addon version updates"
	fi
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

	if [ -z "$digest" ]; then
		echo "ERROR: Failed to determine the Firefox checksum!" >&2
		return 1
	fi

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

	if [ -z "$digest" ]; then
		echo "ERROR: Failed to determine the kubectl checksum!" >&2
		return 1
	fi

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
		echo "- update needed from $current_version"
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
			|= ( .download_url = env(url) | .checksum = env(digest) | .checksum style="double")' "$ARTIFACTS_FILE"
}


# ensure the script is run in the correct directory
if [ ! -d containerize  -o  ! -f "$ARTIFACTS_FILE" ]; then
	echo "ERROR: This script must be run from the RapiDAST repository root directory!" >&2
	exit 1
fi


# scanners/tools to update can be specified as command line arguments, all are
# updated if no argument is specified
if [ $# -eq 0 ]; then
	set -- zap zap-addons firefox trivy kubectl
fi

for scanner in "$@"; do
	case "$scanner" in
		zap)         update_zap ;;
		zap-addons)  update_zap_addons ;;
		firefox)     update_firefox ;;
		trivy)       update_trivy ;;
		kubectl)     update_kubectl ;;
		*)
			echo "ERROR: Unknown scanner or tool '$scanner'" >&2
			exit 1
			;;
	esac
done
