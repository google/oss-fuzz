#!/bin/bash -eux
# Copyright 2025 Google LLC
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
#
# A script to build base images locally.
#
# This script is a wrapper around `docker build` that dynamically fetches the
# official list of images from the Python source of truth, ensuring it never
# goes out of date.
#
# Usage:
#       # Build the 'latest' version of all images.
#       ./all.sh
#
#       # Build the 'ubuntu-24-04' version of all images.
#       ./all.sh ubuntu-24-04
#
################################################################################

# The first argument is the version tag, e.g., 'latest', 'ubuntu-20-04'.
VERSION_TAG=${1:-latest}

# Get the directory where this script is located to find the helper script.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"

# Fetch the official list of images from the Python source of truth.
# This avoids duplicating the image list and ensures this script is always
# up-to-date.
IMAGE_LIST=$(python3 "${SCRIPT_DIR}/list_images.py")

echo "Building version: ${VERSION_TAG}"
echo "Images to build: ${IMAGE_LIST}"

# Loop through the official list of images and build each one.
for image_name in ${IMAGE_LIST}; do
  image_dir="infra/base-images/${image_name}"
  
  if [ "${VERSION_TAG}" == "latest" ]; then
    dockerfile="${image_dir}/Dockerfile"
    tag="gcr.io/oss-fuzz-base/${image_name}"
  else
    dockerfile="${image_dir}/${VERSION_TAG}.Dockerfile"
    tag="gcr.io/oss-fuzz-base/${image_name}:${VERSION_TAG}"
  fi

  if [ ! -f "${dockerfile}" ]; then
    echo "Skipping build for ${image_name}:${VERSION_TAG} - Dockerfile not found at ${dockerfile}"
    continue
  fi

  echo "Building ${tag} from ${dockerfile}..."
  docker build --pull -t "${tag}" -f "${dockerfile}" "${image_dir}"
done

echo "All builds for version ${VERSION_TAG} completed successfully."