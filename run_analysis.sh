#!/bin/bash

RESULTS_DIR=${RESULTS_DIR:-"/tmp/results"}
STATIC_RESULTS_DIR=${STATIC_RESULTS_DIR:-"/tmp/staticResults"}
FILE_WRITE_RESULTS_DIR=${FILE_WRITE_RESULTS_DIR:-"/tmp/writeResults"}
ANALYZED_PACKAGES_DIR=${ANALYZED_PACKAGES_DIR:-"/tmp/analyzedPackages"}
LOGS_DIR=${LOGS_DIR:-"/tmp/dockertmp"}
STRACE_LOGS_DIR=${STRACE_LOGS_DIR:-"/tmp/straceLogs"}
DOCKER_BIN=${DOCKER_BIN:-"docker"}


# function to create directory if it doesn't exist
function create_dir_if_not_exists {
	local dir_path=$1
	if [[ ! -d "$dir_path" ]]; then
		mkdir -p "$dir_path"
		echo "Directory created: $dir_path"
	else
		echo "Directory already exists: $dir_path"
	fi
}


# for pretty printing
LINE="-----------------------------------------"

function print_usage {
	echo "Usage: $0 [-dryrun] [-fully-offline] <analyze args...>"
	echo
	echo $LINE
	echo "Script options"
	echo "  -dryrun"
	echo "    	prints commmand that would be executed and exits"
	echo "  -fully-offline"
	echo "    	completely disables network access for the container runtime"
	echo "    	Analysis will only work when using -local <pkg path> and -nopull."
	echo "    	(see also: -offline)"
	echo "  -nointeractive"
	echo "          disables TTY input and prevents allocating pseudo-tty"
	echo $LINE
	echo
}

function print_package_details {
	echo "Ecosystem:                $ECOSYSTEM"
	echo "Package:                  $PACKAGE"
	echo "Version:                  $VERSION"
	if [[ $LOCAL -eq 1 ]]; then
		LOCATION="$PKG_PATH"
	else
		LOCATION="remote"
	fi

	echo "Location:                 $LOCATION"
}

function print_results_dirs {
	echo "Dynamic analysis results: $RESULTS_DIR"
	echo "Static analysis results:  $STATIC_RESULTS_DIR"
	echo "File write results:       $FILE_WRITE_RESULTS_DIR"
	echo "Analyzed package saved:   $ANALYZED_PACKAGES_DIR"
	echo "Debug logs:               $LOGS_DIR"
	echo "Strace logs:              $STRACE_LOGS_DIR"
}

function sanitize_result_component {
	local value=$1
	value=${value//\//__}
	value=${value//\\/__}
	value=${value//$'\n'/_}
	value=${value//$'\r'/_}
	printf '%s' "$value"
}

function create_stage_dir {
	local output_dir=$1
	local resolved_output
	resolved_output=$(realpath "$output_dir" 2>/dev/null) || return 1
	if [[ -z "$resolved_output" || "$resolved_output" == "/" || ! -d "$resolved_output" ]]; then
		echo "Refusing invalid staging parent: $output_dir" >&2
		return 1
	fi
	local stage_dir
	stage_dir=$(mktemp -d "${resolved_output%/}/.analysis-stage.XXXXXX") || return 1
	if [[ -z "$stage_dir" || ! -d "$stage_dir" ]]; then
		echo "Failed to create staging directory below: $output_dir" >&2
		return 1
	fi
	printf '%s' "$stage_dir"
}

function result_base_in_use {
	local output_dir=$1
	local result_base=$2
	local existing existing_name
	for existing in "$output_dir"/*; do
		existing_name=$(basename "$existing")
		if [[ "$existing_name" == "$result_base".* || "$existing_name" == "$result_base"-* ]]; then
			return 0
		fi
	done
	return 1
}

function archive_stage_files {
	local stage_dir=$1
	local output_dir=$2
	local file filename extension new_name run_base duplicate_sequence
	local run_sequence=2
	local archive_status=0
	if [[ -z "$stage_dir" || ! -d "$stage_dir" || -z "$output_dir" || ! -d "$output_dir" ]]; then
		echo "Refusing to archive from invalid staging/output paths: '$stage_dir' -> '$output_dir'" >&2
		return 1
	fi
	shopt -s nullglob dotglob
	run_base=$RESULTS_PREFIX
	while result_base_in_use "$output_dir" "$run_base"; do
		run_base="${RESULTS_PREFIX}.${run_sequence}"
		run_sequence=$((run_sequence+1))
	done
	for file in "$stage_dir"/*; do
		filename=$(basename "$file")
		if [[ -d "$file" ]]; then
			new_name="$output_dir/${run_base}-${filename}"
		else
			extension="${filename##*.}"
			new_name="$output_dir/${run_base}.${extension}"
			duplicate_sequence=2
			while [[ -e "$new_name" ]]; do
				new_name="$output_dir/${run_base}.${duplicate_sequence}.${extension}"
				duplicate_sequence=$((duplicate_sequence+1))
			done
		fi
		if mv "$file" "$new_name"; then
			echo "Archived $file as $new_name"
		else
			echo "Failed to archive $file as $new_name" >&2
			archive_status=1
		fi
	done
	shopt -u nullglob dotglob
	if ! rmdir "$stage_dir" 2>/dev/null; then
		echo "Warning: non-empty staging directory retained at $stage_dir" >&2
		archive_status=1
	fi
	return $archive_status
}


args=("$@")

HELP=0
DRYRUN=0
LOCAL=0
DOCKER_OFFLINE=0
INTERACTIVE=1

ECOSYSTEM=""
PACKAGE=""
VERSION=""
PKG_PATH=""
MOUNTED_PKG_PATH=""

i=0
while [[ $i -lt $# ]]; do
	case "${args[$i]}" in
		"-dryrun")
			DRYRUN=1
			unset "args[i]" # this argument is not passed to analysis image
			;;
		"-fully-offline")
			DOCKER_OFFLINE=1
			unset "args[i]" # this argument is not passed to analysis image
			;;
		"-nointeractive")
			INTERACTIVE=0
			unset "args[i]" # this argument is not passed to analysis image
			;;
		"-help")
			HELP=1
			;;
		"-local")
			# need to create a mount to pass the package archive to the docker image
			LOCAL=1
			i=$((i+1))
			# Resolve an existing archive without GNU-specific realpath options.
			PKG_PATH=$(realpath "${args[$i]}" 2>/dev/null)
			if [[ -z "$PKG_PATH" ]]; then
				echo "-local must point to an existing package archive"
				exit 255
			fi
			PKG_FILE=$(basename "$PKG_PATH")
			MOUNTED_PKG_PATH="/$PKG_FILE"
			# need to change the path passed to analysis image to the mounted one
			# which is stripped of host path info
			args[$i]="$MOUNTED_PKG_PATH"
			;;
		"-ecosystem")
			i=$((i+1))
			ECOSYSTEM="${args[$i]}"
			;;
		"-package")
			i=$((i+1))
			PACKAGE="${args[$i]}"
			;;
		"-version")
			i=$((i+1))
			VERSION="${args[$i]}"
			;;
	esac
	i=$((i+1))
done

if [[ $# -eq 0 ]]; then
	HELP=1
fi

DOCKER_OPTS=("run" "--cgroupns=host" "--privileged" "--rm")

# On development systems, we mount /var/lib/containers so that sandbox images can be
# shared between the host system and the analysis image. However, this requires the
# directory to be backed by a non-overlay filesystem.
# In some environments, e.g. GitHub Codespaces, this is not the case, and we need to
# specify a different mount dir which is backed by a non-overlay filesystem.

# Checks that the given mountpoint has the given filesystem mount type
function is_mount_type() {
	if ! command -v findmnt >/dev/null 2>&1; then
		return 1
	fi
	if [[ $(findmnt -T "$2" -n -o FSTYPE) == "$1" ]]; then
		return 0
	else
		return 1
	fi
}

CONTAINER_MOUNT_DIR="/var/lib/containers"

if [[ -n "$CONTAINER_DIR_OVERRIDE" ]]; then
	CONTAINER_MOUNT_DIR="$CONTAINER_DIR_OVERRIDE"
elif [[ $CODESPACES == "true" ]]; then
	CONTAINER_MOUNT_DIR=$(mktemp -d)
	echo "GitHub Codespaces environment detected, using $CONTAINER_MOUNT_DIR for container mount"
elif is_mount_type overlay /var/lib; then
	if is_mount_type overlay /tmp && ! is_mount_type tmpfs /tmp; then
		CONTAINER_MOUNT_DIR=$(mktemp -d)
		echo "Warning: /var/lib is an overlay mount, using $CONTAINER_MOUNT_DIR for container mount"
	else
		echo "Environment error: /var/lib is an overlay mount, please set CONTAINER_DIR_OVERRIDE to a directory that is backed by a non-overlay filesystem"
		exit 1
	fi
fi


ANALYSIS_IMAGE=gcr.io/ossf-malware-analysis/analysis

ANALYSIS_ARGS=("analyze" "-dynamic-bucket" "file:///results/" "-file-writes-bucket" "file:///writeResults/" "-static-bucket" "file:///staticResults/" "-analyzed-pkg-bucket" "file:///analyzedPackages/" "-execution-log-bucket" "file:///results")

# Add the remaining command line arguments
ANALYSIS_ARGS=("${ANALYSIS_ARGS[@]}" "${args[@]}")

if [[ $HELP -eq 1 ]]; then
	print_usage
	exit 0
fi

if [[ $INTERACTIVE -eq 1 ]]; then
	DOCKER_OPTS+=("-ti")
fi

if [[ $DOCKER_OFFLINE -eq 1 ]]; then
	DOCKER_OPTS+=("--network" "none")
fi

if [[ -n "$ECOSYSTEM" && -n "$PACKAGE" ]]; then
	PACKAGE_DEFINED=1
else
	PACKAGE_DEFINED=0
fi

if [[ $PACKAGE_DEFINED -eq 1 ]]; then
	echo $LINE
	echo "Package Details"
	print_package_details
	echo $LINE
fi

# If dry run, just print the command and exit
if [[ $DRYRUN -eq 1 ]]; then
	DOCKER_MOUNTS=("-v" "$CONTAINER_MOUNT_DIR:/var/lib/containers" "-v" "$RESULTS_DIR:/results" "-v" "$STATIC_RESULTS_DIR:/staticResults" "-v" "$FILE_WRITE_RESULTS_DIR:/writeResults" "-v" "$LOGS_DIR:/tmp" "-v" "$ANALYZED_PACKAGES_DIR:/analyzedPackages" "-v" "$STRACE_LOGS_DIR:/straceLogs")
	if [[ $LOCAL -eq 1 ]]; then
		DOCKER_MOUNTS+=("-v" "$PKG_PATH:$MOUNTED_PKG_PATH:ro")
	fi
	echo "Analysis command (dry run)"
	echo
	echo "$DOCKER_BIN" "${DOCKER_OPTS[@]}" "${DOCKER_MOUNTS[@]}" "$ANALYSIS_IMAGE" "${ANALYSIS_ARGS[@]}"

	echo
	exit 0
fi

# Else continue execution
if [[ $PACKAGE_DEFINED -eq 1 ]]; then
	echo "Analysing package"
	echo
fi

if [[ $LOCAL -eq 1 ]] && [[ ! -f "$PKG_PATH" || ! -r "$PKG_PATH" ]]; then
	echo "Error: path $PKG_PATH does not refer to a file or is not readable"
	echo
	exit 1
fi

sleep 1 # Allow time to read info above before executing

create_dir_if_not_exists "$RESULTS_DIR"
create_dir_if_not_exists "$STATIC_RESULTS_DIR"
create_dir_if_not_exists "$FILE_WRITE_RESULTS_DIR"
create_dir_if_not_exists "$ANALYZED_PACKAGES_DIR"
create_dir_if_not_exists "$LOGS_DIR"
create_dir_if_not_exists "$STRACE_LOGS_DIR"

# Each analysis writes into private staging directories.  The previous version
# mounted the shared output directories directly and then renamed every file in
# them, which could relabel historical results as the current package.
RUN_RESULTS_DIR=$(create_stage_dir "$RESULTS_DIR") || exit 1
RUN_STATIC_RESULTS_DIR=$(create_stage_dir "$STATIC_RESULTS_DIR") || exit 1
RUN_FILE_WRITE_RESULTS_DIR=$(create_stage_dir "$FILE_WRITE_RESULTS_DIR") || exit 1
RUN_ANALYZED_PACKAGES_DIR=$(create_stage_dir "$ANALYZED_PACKAGES_DIR") || exit 1
RUN_LOGS_DIR=$(create_stage_dir "$LOGS_DIR") || exit 1
RUN_STRACE_LOGS_DIR=$(create_stage_dir "$STRACE_LOGS_DIR") || exit 1

DOCKER_MOUNTS=("-v" "$CONTAINER_MOUNT_DIR:/var/lib/containers" "-v" "$RUN_RESULTS_DIR:/results" "-v" "$RUN_STATIC_RESULTS_DIR:/staticResults" "-v" "$RUN_FILE_WRITE_RESULTS_DIR:/writeResults" "-v" "$RUN_LOGS_DIR:/tmp" "-v" "$RUN_ANALYZED_PACKAGES_DIR:/analyzedPackages" "-v" "$RUN_STRACE_LOGS_DIR:/straceLogs")
if [[ $LOCAL -eq 1 ]]; then
	# The archive is untrusted input and never needs to be writable.
	DOCKER_MOUNTS+=("-v" "$PKG_PATH:$MOUNTED_PKG_PATH:ro")
fi

"$DOCKER_BIN" "${DOCKER_OPTS[@]}" "${DOCKER_MOUNTS[@]}" "$ANALYSIS_IMAGE" "${ANALYSIS_ARGS[@]}"

DOCKER_EXIT_CODE=$?
# define the results naming convention
RESULTS_PREFIX="$(sanitize_result_component "$ECOSYSTEM")-$(sanitize_result_component "$PACKAGE")-$(sanitize_result_component "$VERSION")"

# Preserve both successful results and partial/error telemetry, but only from
# this run's staging directories.
ARCHIVE_EXIT_CODE=0
archive_stage_files "$RUN_RESULTS_DIR" "$RESULTS_DIR" || ARCHIVE_EXIT_CODE=1
archive_stage_files "$RUN_STATIC_RESULTS_DIR" "$STATIC_RESULTS_DIR" || ARCHIVE_EXIT_CODE=1
archive_stage_files "$RUN_FILE_WRITE_RESULTS_DIR" "$FILE_WRITE_RESULTS_DIR" || ARCHIVE_EXIT_CODE=1
archive_stage_files "$RUN_ANALYZED_PACKAGES_DIR" "$ANALYZED_PACKAGES_DIR" || ARCHIVE_EXIT_CODE=1
archive_stage_files "$RUN_LOGS_DIR" "$LOGS_DIR" || ARCHIVE_EXIT_CODE=1
archive_stage_files "$RUN_STRACE_LOGS_DIR" "$STRACE_LOGS_DIR" || ARCHIVE_EXIT_CODE=1
if [[ $DOCKER_EXIT_CODE -eq 0 && $ARCHIVE_EXIT_CODE -ne 0 ]]; then
	DOCKER_EXIT_CODE=1
fi

if [[ $PACKAGE_DEFINED -eq 1 ]]; then
echo
echo $LINE
	if [[ $DOCKER_EXIT_CODE -eq 0 ]]; then
		echo "Finished analysis"
		echo
		print_package_details
		print_results_dirs

	else
		echo "Analysis failed"
		echo
		echo "docker/archive process exited with code $DOCKER_EXIT_CODE"
		echo
		print_package_details
	fi

echo $LINE
fi

exit $DOCKER_EXIT_CODE
