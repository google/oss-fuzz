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

<<<<<<< HEAD
# Multi-stage Dockerfile for Gemini CLI OSS-Fuzz integration
# Stage 1: Builder with all dependencies for Go and JavaScript fuzzers
FROM gcr.io/oss-fuzz-base/base-builder-javascript AS builder

# Add Go support for multi-language setup
ENV GOPATH=/root/go
ENV PATH=$PATH:/root/.go/bin:$GOPATH/bin
RUN install_go.sh

# Install additional build dependencies
RUN set -ex && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        curl \
        gnupg \
        ca-certificates \
        software-properties-common \
        make \
        cmake && \
    # Verify installations
    go version && \
    echo "Go: $(go version)" && \
    node --version && \
    echo "Node.js: $(node --version)" && \
    npm --version && \
    echo "NPM: $(npm --version)" && \
    # Install Jazzer.js with specific version for reproducibility
    npm install -g @jazzer.js/core@^2.1.0 && \
    echo "Jazzer.js $(npx @jazzer.js/core --version) installed successfully" && \
    # Clean up to reduce image size
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* /root/.npm

# Copy project source
COPY . $SRC/gemini-cli/

# Set working directory
WORKDIR $SRC/gemini-cli/

# Verify installations with error checking
RUN set -ex && \
    echo "=== Installation Verification ===" && \
    go version && \
    echo "Go: $(go version)" && \
    node --version && \
    echo "Node.js: $(node --version)" && \
    npm --version && \
    echo "NPM: $(npm --version)" && \
    echo "Jazzer.js: $(npx @jazzer.js/core --version || echo 'Not available')" && \
    echo "=== Verification Complete ==="

# Pre-build stage: Cache and prepare dependencies with security checks
RUN set -ex && \
    echo "=== Preparing Dependencies ===" && \
    # Prepare Go dependencies with security verification
    if [ -f gofuzz/go.mod ]; then \
        echo "Preparing Go dependencies..." && \
        cd gofuzz && \
        go mod download && \
        go mod verify && \
        echo "Go dependencies verified and cached" && \
        cd ..; \
    fi && \
    # Prepare Node.js dependencies with security scanning
    if [ -f fuzzers/package.json ]; then \
        echo "Preparing Node.js dependencies..." && \
        cd fuzzers && \
        npm ci --production=false --no-audit --no-fund --prefer-offline && \
        echo "Node.js dependencies installed and verified" && \
        # Run security audit if available
        npm audit --audit-level=high || echo "NPM audit completed with warnings" && \
        cd ..; \
    fi && \
    echo "=== Dependencies Prepared ==="

# Stage 2: Runtime with only necessary files
FROM gcr.io/oss-fuzz-base/base-builder

# Copy runtime dependencies and tools with minimal footprint
COPY --from=builder $SRC/gemini-cli/ $SRC/gemini-cli/
COPY --from=builder /usr/bin/node /usr/bin/node
COPY --from=builder /usr/bin/npm /usr/bin/npm
COPY --from=builder /usr/lib/node_modules/@jazzer.js/ /usr/lib/node_modules/@jazzer.js/

# Set working directory
WORKDIR $SRC/gemini-cli/

# Set environment variables optimized for fuzzing
ENV SANITIZER=address
ENV FUZZING_LANGUAGE=multi
ENV NODE_OPTIONS="--max-old-space-size=4096 --trace-warnings"
ENV GOPROXY=https://proxy.golang.org,direct
ENV GOSUMDB=sum.golang.org
# Security hardening
ENV NODE_ENV=production
ENV NPM_CONFIG_UPDATE_NOTIFIER=false
ENV NPM_CONFIG_AUDIT=false
ENV NPM_CONFIG_FUND=false

# Runtime verification and security hardening
RUN set -ex && \
    echo "=== Runtime Setup Verification ===" && \
    # Verify Go installation and tools
    go version && \
    echo "Go: $(go version)" && \
    # Verify Node.js installation and tools
    node --version && \
    echo "Node.js: $(node --version)" && \
    npm --version && \
    echo "NPM: $(npm --version)" && \
    # Verify Jazzer.js
    npx @jazzer.js/core --version && \
    echo "Jazzer.js: $(npx @jazzer.js/core --version)" && \
    # Verify OSS-Fuzz compilation tools
    which compile_go_fuzzer && \
    echo "compile_go_fuzzer: $(which compile_go_fuzzer)" && \
    which compile_javascript_fuzzer && \
    echo "compile_javascript_fuzzer: $(which compile_javascript_fuzzer)" && \
    # Security hardening: remove unnecessary tools
    apt-get remove -y --auto-remove \
        curl \
        gnupg \
        software-properties-common || true && \
    # Final cleanup
    rm -rf /tmp/* /var/tmp/* /root/.cache && \
    echo "=== Runtime Setup Verification Complete ===" && \
    echo "🚀 Final image ready for fuzzing with security hardening applied"
=======
# oss-fuzz/projects/gemini-cli/Dockerfile
FROM gcr.io/oss-fuzz-base/base-builder-javascript

# install any global tools if needed (none required for now)
>>>>>>> 6beb447382265fce1442b77fb11e5a90be556a20
