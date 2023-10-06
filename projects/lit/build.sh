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

# Install dependencies.
npm install -g @babel/cli
npm install --save-dev @babel/core \
	@babel/plugin-transform-modules-commonjs \
	@babel/preset-typescript \
	@jazzer.js/core

# Build Lit
npm install
npm run build

change_type_to_commonjs "$SRC/lit"

# Build Fuzzers
# The last bits are necessary to make the fuzzer run in the OSS-Fuzz execution
# environment.
compile_javascript_fuzzer lit fuzz.js -i lit --sync &&
	pushd "$OUT" &&
	cp -r lit/babel.config.json lit/node_modules "$(pwd)" &&
	popd
