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

set -eux


export PROJECT=oss-fuzz
export IMAGE=gcr.io/oss-fuzz-base/triage-party
export SERVICE_NAME=triage-party
export CONFIG_FILE=config/examples/oss-fuzz.yaml


# Copy triage-party into tmp dir, and copy config into correct spot
readonly clean_repo=$(mktemp -d)
git clone --depth 1 https://github.com/google/triage-party.git "${clean_repo}"
cp ./oss-fuzz.yaml "${clean_repo}"/${CONFIG_FILE}
cd "${clean_repo}"


docker build -t "${IMAGE}" --build-arg "CFG=./${CONFIG_FILE}" .
docker push "${IMAGE}" || exit 2

readonly token="$(cat "${GITHUB_TOKEN_PATH}")"
gcloud beta run deploy "${SERVICE_NAME}" \
    --project "${PROJECT}" \
    --image "${IMAGE}" \
    --set-env-vars="GITHUB_TOKEN=${token},PERSIST_BACKEND=cloudsql,PERSIST_PATH=tp:${DB_PASS}@tcp(oss-fuzz/us-central1/triage-party)/tp" \
    --allow-unauthenticated \
    --region us-central1 \
    --memory 384Mi \
    --platform managed
