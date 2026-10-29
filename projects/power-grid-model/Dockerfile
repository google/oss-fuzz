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

FROM gcr.io/oss-fuzz-base/base-builder

# Build tooling. base-builder ships an older apt CMake than power-grid-model
# requires (>= 3.23), so a recent CMake is installed from Kitware below.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ninja-build wget ca-certificates zip && \
    rm -rf /var/lib/apt/lists/*

# --- Modern CMake (power-grid-model needs >= 3.23) ---------------------------
RUN wget -qO /tmp/cmake.sh \
        https://github.com/Kitware/CMake/releases/download/v3.30.5/cmake-3.30.5-linux-x86_64.sh && \
    sh /tmp/cmake.sh --skip-license --prefix=/usr/local && \
    rm /tmp/cmake.sh

# --- Header-only C++ dependencies (installed to /usr/local for find_package) --
# Boost headers. base-builder compiles with libc++, which dropped the
# std::unary_function that older Boost.ContainerHash (the apt libboost-dev,
# ~1.71) still derives from — so the apt Boost fails to compile here. Boost
# >= 1.81 rewrote ContainerHash without it. PGM and msgpack-cxx use Boost
# header-only, so only the headers are installed (no compiled libraries).
# Installed before msgpack-cxx, whose configure looks for Boost.
RUN wget -qO /tmp/boost.tar.gz \
        https://archives.boost.io/release/1.84.0/source/boost_1_84_0.tar.gz && \
    tar -xzf /tmp/boost.tar.gz -C /tmp && \
    cp -r /tmp/boost_1_84_0/boost /usr/local/include/ && \
    rm -rf /tmp/boost*

# Eigen3 (CONFIG)
RUN wget -qO /tmp/eigen.tar.gz \
        https://gitlab.com/libeigen/eigen/-/archive/3.4.0/eigen-3.4.0.tar.gz && \
    tar -xzf /tmp/eigen.tar.gz -C /tmp && \
    cmake -S /tmp/eigen-3.4.0 -B /tmp/eigen-build -DBUILD_TESTING=OFF && \
    cmake --install /tmp/eigen-build && \
    rm -rf /tmp/eigen*

# nlohmann_json (CONFIG)
RUN wget -qO /tmp/json.tar.gz \
        https://github.com/nlohmann/json/archive/refs/tags/v3.11.3.tar.gz && \
    tar -xzf /tmp/json.tar.gz -C /tmp && \
    cmake -S /tmp/json-3.11.3 -B /tmp/json-build -DJSON_BuildTests=OFF && \
    cmake --install /tmp/json-build && \
    rm -rf /tmp/json*

# msgpack-cxx (CONFIG) — header-only C++ interface. Built with
# MSGPACK_USE_BOOST=OFF: PGM only uses core msgpack (packer/sbuffer/parse/
# null_visitor), no boost adaptors, so disabling Boost avoids msgpack's own
# find_package(Boost) (which would demand a BoostConfig.cmake our headers-only
# Boost install does not provide) and propagates MSGPACK_NO_BOOST to consumers.
RUN wget -qO /tmp/msgpack.tar.gz \
        https://github.com/msgpack/msgpack-c/releases/download/cpp-7.0.0/msgpack-cxx-7.0.0.tar.gz && \
    tar -xzf /tmp/msgpack.tar.gz -C /tmp && \
    cmake -S /tmp/msgpack-cxx-7.0.0 -B /tmp/msgpack-build \
        -DMSGPACK_CXX20=ON -DMSGPACK_BUILD_TESTS=OFF -DMSGPACK_USE_BOOST=OFF && \
    cmake --install /tmp/msgpack-build && \
    rm -rf /tmp/msgpack*

# CLI11 (CONFIG) — header-only. The root CMakeLists.txt requires it
# unconditionally for the power_grid_model_cli_backend target. build.sh never
# builds that target (only power_grid_model_c), so CLI11 is needed at configure
# time only.
RUN wget -qO /tmp/cli11.tar.gz \
        https://github.com/CLIUtils/CLI11/archive/refs/tags/v2.7.2.tar.gz && \
    tar -xzf /tmp/cli11.tar.gz -C /tmp && \
    cmake -S /tmp/CLI11-2.7.2 -B /tmp/cli11-build \
        -DCLI11_BUILD_TESTS=OFF -DCLI11_BUILD_EXAMPLES=OFF -DCLI11_BUILD_DOCS=OFF && \
    cmake --install /tmp/cli11-build && \
    rm -rf /tmp/cli11* /tmp/CLI11*

# --- Target project ----------------------------------------------------------
# The fuzz harnesses, seed corpora, and dictionary live upstream under
# tests/fuzzer/ (added in PowerGridModel/power-grid-model#1617), so cloning the
# repository brings the fuzzing material with it — nothing is vendored here.
RUN git clone --depth 1 https://github.com/PowerGridModel/power-grid-model.git \
        $SRC/power-grid-model

COPY build.sh $SRC/
WORKDIR $SRC/power-grid-model
