#!/bin/bash -eux
# Copyright 2026 Google LLC
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

# Ensure the project ID is provided as an argument
if [ $# -ne 1 ]; then
  echo "Usage: $0 <gcp-project-id>"
  exit 1
fi

PROJECT_ID=$1
BUCKET_NAME="oss-fuzz-blog"

# Change to the blog directory
cd "$(dirname "$0")"

# Build the site using Docker to guarantee Hugo version dependencies
echo "Building the blog via Docker..."
docker build -t oss-fuzz-blog-builder .

# Extract compiled static files from the built container
echo "Extracting compiled site..."
docker run --name temp-blog-container -d oss-fuzz-blog-builder
if [ -d "./public" ]; then
  rm -rf ./public
fi
docker cp temp-blog-container:/oss-fuzz-blog/page/public ./public
docker rm -f temp-blog-container

# Backup the current live version from GCS to a local backup directory
BACKUP_DIR="./backup_$(date +%Y%m%d_%H%M%S)"
echo "Creating local backup of current production site to ${BACKUP_DIR}..."
mkdir -p "${BACKUP_DIR}"
gcloud storage cp -r "gs://${BUCKET_NAME}/*" "${BACKUP_DIR}" --project="${PROJECT_ID}"

# Deploy to the production Google Cloud Storage bucket
echo "Deploying static files to gs://${BUCKET_NAME}..."
gcloud storage rsync -r ./public "gs://${BUCKET_NAME}" --delete-unmatched-destination-objects --project="${PROJECT_ID}"

echo "Deployment completed successfully!"

