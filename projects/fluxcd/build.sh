#!/bin/bash -eu
# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

# This code improves the use of Go Native by:
# - Dynamically discovering and building all fuzz tests within the project root path.
# - Supporting single (during PR checks) or multiple repositories (oss-fuzz).
# - Enabling execution via CI builds and Makefile targets for each repo.

GOPATH="${GOPATH:-/root/go}"
ORG_ROOT="${ORG_ROOT:-${GOPATH}/src/github.com/fluxcd}"
PREBUILD_SCRIPT_PATH="${PREBUILD_SCRIPT_PATH:-tests/fuzz/oss_fuzz_prebuild.sh}"
POSTBUILD_SCRIPT_PATH="${POSTBUILD_SCRIPT_PATH:-tests/fuzz/oss_fuzz_postbuild.sh}"

# source_prebuild_script sources the prebuild script, which executes project-specific
# code and exposes environment variables that are needed during the generic build process.
#
# Examples of usage may be organising directory structure for embedding
# files, downloading artifacts or setting environment variables.
function source_prebuild_script(){
	if [ -f "${PREBUILD_SCRIPT_PATH}" ]; then
		# shellcheck source=/dev/null
		. "${PREBUILD_SCRIPT_PATH}"
	fi
}

# source_postbuild_script sources the postbuild script, which executes project-specific
# code and unset environment variables that may break follow-up processes.
function source_postbuild_script(){
	if [ -f "${POSTBUILD_SCRIPT_PATH}" ]; then
		# shellcheck source=/dev/null
		. "${POSTBUILD_SCRIPT_PATH}"
	fi
}

# go_native_build_all_fuzzers builds all Go Native fuzz tests defined in modules within
# the given project dir.
#
# Args:
# 	project_dir
function go_native_build_all_fuzzers(){
	local project_path="$1"

	cd "${project_path}"

	source_prebuild_script

	modules=$(find . -mindepth 1 -maxdepth 4 -type f -name 'go.mod' | cut -c 3- | sed 's|/[^/]*$$||' | sort -u | sed 's;/go.mod;;g' | sed 's;go.mod;.;g')
	for module in ${modules}; do
		cd "${project_path}/${module}"

		local test_files
		test_files=$(grep -r --include='**_test.go' --files-with-matches 'func Fuzz' . || echo "")
		if [ -z "${test_files}" ]; then
			continue
		fi

		# go-118-fuzz-build is required for each module.
		go get -u github.com/AdamKorcz/go-118-fuzz-build/testing

		# The go get command above can affect transient dependencies, may lead
		# to the go.sym to become out of sync, which would cause build to break.
		# go mod tidy will only work if the current module has a reference
		# to the above dependency, so we create one.
		local pkgName
		pkgName="$(grep -h '^package ' -- *.go | head -n 1)"
		if [ -z "${test_files}" ]; then
			pkgName="package fuzz"
		fi
		
		cat <<EOF > dep-placeholder.go
${pkgName}

import _ "github.com/AdamKorcz/go-118-fuzz-build/testing"
EOF
		# With the reference above, this updates go.sum.
		go mod tidy

		# Iterate through all Go Fuzz targets, compiling each into a fuzzer.
		for file in ${test_files}; do
			# If the subdir is a module, skip this file, as it will be handled
			# at the next iteration of the outer loop. 
			if [ -f "$(dirname "${file}")/go.mod" ]; then
				continue
			fi

			targets=$(grep -oP 'func \K(Fuzz\w*)' "${file}")
			for target_name in ${targets}; do
				local module_name
				local fuzzer_name
				local target_dir

				# Transform module path into module name (e.g. git/libgit2 to git_libgit2).
				module_name="${module/\//_}_"
				# If module equal '._', use empty string instead.
				module_name="${module/#%._}"

				# Compose fuzzer name based on the lowercase version of the func names.
				fuzzer_name="${target_name,,}"
				# The module name is added after the fuzz prefix, for better discoverability.
				fuzzer_name="${target_name/fuzz_/fuzz_${module_name}}"
				target_dir=$(dirname "${file}")

				echo "Building ${file}.${target_name} into ${fuzzer_name}"
				compile_native_go_fuzzer "${target_dir}" "${target_name}" "${fuzzer_name}"
			done
		done
	done
}

function loop_through_org_repositories(){
	local repos=""
	repos="$(find "${ORG_ROOT}" -type d -mindepth 1 -maxdepth 1)"
	for repo in ${repos}; do
		go_native_build_all_fuzzers "${repo}"
	done
}

function main(){
	# If SRC is set to a Flux project, only its fuzzers will be built.
	if grep -h '^module github.com/fluxcd/' "${SRC}/go.mod"; then
		echo "Building Go Native fuzzers for ${SRC}"
		go_native_build_all_fuzzers "${SRC}"
		exit $?
	fi
	
	echo "Going through all repositories in ${ORG_ROOT}"
	loop_through_org_repositories 
}

main
