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

#!/bin/bash

# Script to manage seed corpora for Gemini CLI fuzzing

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORPORA_DIR="${SCRIPT_DIR}/corpora"

# Create corpora directory if it doesn't exist
mkdir -p "${CORPORA_DIR}"

echo "Seed corpora directory: ${CORPORA_DIR}"

# Add basic seed files for fuzzing
echo "Creating basic seed files..."

# HTTP header seeds
echo -e "Content-Type: application/json\nAuthorization: Bearer token123" > "${CORPORA_DIR}/http_headers.seed"
echo -e "User-Agent: Mozilla/5.0\nAccept: */*" > "${CORPORA_DIR}/http_headers2.seed"

# JSON seeds
echo '{"key": "value", "number": 123}' > "${CORPORA_DIR}/json.seed"
echo '["item1", "item2", {"nested": true}]' > "${CORPORA_DIR}/json2.seed"

# URL seeds
echo "https://example.com/path?param=value" > "${CORPORA_DIR}/url.seed"
echo "http://localhost:8080/api/v1/data" > "${CORPORA_DIR}/url2.seed"

echo "Seed corpora setup complete."
