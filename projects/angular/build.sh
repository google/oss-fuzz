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
  echo "$new_package_json" > package.json

}

function copy_bazel_build_into_build_dir() {
  local package=$1
  local source_dir=$SRC/angular/dist/bin/packages/$package
  local destination_dir=$2
  local extensions=("mjs" "d.ts")  # Add the extensions you want to copy here
  mkdir -p "$destination_dir"
  cp "$SRC"/angular/babel.config.json "$destination_dir"

  # Copy files recursively from source directory to destination directory
  find "$source_dir" -type f -name "*.${extensions[0]}" -o -name "*.${extensions[1]}" |
  while read -r file; do
    # Get the relative path of the file (relative to the source directory)
    relative_path="${file#$source_dir}"

    # Remove leading slash if present
    relative_path="${relative_path#/}"

    # Create the directory structure inside the destination directory
    mkdir -p "$destination_dir/$(dirname "$relative_path")"

    # Copy the file to the destination directory
    cp "$file" "$destination_dir/$relative_path"
  done
}

function rename_mjs_files() {
  local destination_dir=$1
  find "$destination_dir" -type f -name "*.mjs" |
  while read -r file; do
    filename="${file##*/}"
    extension="${filename##*.}"

    # Check if the file has the "mjs" extension
    if [ "$extension" = "mjs" ]; then
      new_filename="${file%.mjs}.js"
      mv "$file" "$new_filename"
    fi
  done
}


function build_package() {
  local package=$1
  local package_build_dir=$SRC/$package-build

  yarn bazel build packages/"$package"
  copy_bazel_build_into_build_dir "$package" "$package_build_dir"

  rename_mjs_files "$package_build_dir"
  chmod +w "$package_build_dir"

  mkdir -p "$package_build_dir"
  cp "$SRC"/angular/packages/"$package"/package.json "$package_build_dir"

  pushd "$package_build_dir"

  remove_dev_dependencies
  npm install

  npm install --save-dev @babel/core @babel/plugin-transform-modules-commonjs
  npm install --save-dev @jazzer.js/core

  transform_dir_into_commonjs "$package_build_dir"

  change_type_to_commonjs "$package_build_dir"
  popd

  mkdir -p "$SRC"/angular/"$package"
  cp "$package_build_dir"/* "$SRC"/angular/"$package"/ -r
  rm "$package_build_dir" -r

}

npm install --global yarn patch-package husky @babel/cli
yarn install

mkdir "$OUT"/angular

build_package compiler

# Build Fuzzers.
compile_javascript_fuzzer angular/compiler fuzz_tests/fuzz_parse_template --sync
compile_javascript_fuzzer angular/compiler fuzz_tests/fuzz_parser --sync

