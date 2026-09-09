# Copyright 2025 The OSS-Fuzz project authors
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

# OSS-Fuzz integration for Model Context Protocol (MCP)
# Python/Atheris setup per OSS-Fuzz Python guide
FROM gcr.io/oss-fuzz-base/base-builder-python

# Install any additional Python deps needed by the fuzzer harness
# jsonschema is required by the harness to validate fuzzed JSON against MCP schema
RUN python3 -m pip install --no-cache-dir --upgrade pip \
    && python3 -m pip install --no-cache-dir jsonschema pyinstaller

# Fetch target repository (schemas and docs)
RUN git clone https://github.com/modelcontextprotocol/modelcontextprotocol.git $SRC/modelcontextprotocol

# Set workdir to repo (not strictly required, but convenient for builds)
WORKDIR $SRC/modelcontextprotocol

# Copy build script and fuzzers into $SRC for build step
COPY build.sh mcp_schema_fuzzer.py $SRC/
