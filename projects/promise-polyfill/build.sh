#!/bin/bash -eu
# Copyright 2023 Google LLC
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

function change_type_to_commonjs() {
	# Find all package.json files inside the node_modules directory
	find "$1" -name "package.json" -type f | while read -r package_file; do
		# Check if the file contains the "type" field
		if grep -q '"type": "module"' "$package_file"; then
			# Replace "type": "module" with "type": "commonjs"
			sed -i 's/"type": "module"/"type": "commonjs"/' "$package_file"
			echo "Updated $package_file"
		fi
	done
}

function transform_dir_into_commonjs() {
	babel "$1" --keep-file-extension -D -d "$1"_commonjs
	rm -r "$1"
	mv "$1"_commonjs "$1"
}

function remove_dev_dependencies() {
	package_json=$(cat package.json)

	# Remove the "devDependencies" item from package.json
	new_package_json=$(echo "$package_json" | jq 'del(.devDependencies)')

	# Overwrite the package.json file with the updated content
	echo "$new_package_json" >package.json

}

# Install dependencies.
remove_dev_dependencies

npm install -g @babel/cli
npm install --save-dev @babel/core @babel/plugin-transform-modules-commonjs

transform_dir_into_commonjs "$SRC/promise-polyfill/src"
transform_dir_into_commonjs "$SRC/promise-polyfill/node_modules"

npm install --save-dev @jazzer.js/core

change_type_to_commonjs "$SRC/promise-polyfill"

# Build Fuzzers.
compile_javascript_fuzzer promise-polyfill fuzz -i promise-polyfill
