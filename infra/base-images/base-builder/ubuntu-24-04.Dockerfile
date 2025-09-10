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

FROM base-clang:ubuntu-24-04

COPY install_deps.sh /
RUN /install_deps.sh && rm /install_deps.sh

# Build and install latest Python 3.11.
ENV PYTHON_VERSION 3.11.13
RUN PYTHON_DEPS="\
        zlib1g-dev \
        libncurses-dev \
        libgdbm-dev \
        libnss3-dev \
        libssl-dev \
        libsqlite3-dev \
        libreadline-dev \
        libffi-dev \
        libbz2-dev \
        liblzma-dev" && \
    unset CFLAGS CXXFLAGS && \
    apt-get install -y $PYTHON_DEPS && \
    cd /tmp && \
    curl -O https://www.python.org/ftp/python/$PYTHON_VERSION/Python-$PYTHON_VERSION.tar.xz && \
    tar -xvf Python-$PYTHON_VERSION.tar.xz && \
    cd Python-$PYTHON_VERSION && \
    ./configure --enable-optimizations --enable-shared && \
    make -j$(nproc) && \
    make install && \
    ldconfig && \
    ln -s /usr/local/bin/python3 /usr/local/bin/python && \
    cd .. && \
    rm -r /tmp/Python-$PYTHON_VERSION.tar.xz /tmp/Python-$PYTHON_VERSION && \
    rm -rf /usr/local/lib/python${PYTHON_VERSION%.*}/test && \
    python3 -m ensurepip && \
    python3 -m pip install --upgrade pip && \
    apt-get remove -y $PYTHON_DEPS # https://github.com/google/oss-fuzz/issues/3888


ENV CCACHE_VERSION 4.10.2
RUN cd /tmp && curl -OL https://github.com/ccache/ccache/releases/download/v$CCACHE_VERSION/ccache-$CCACHE_VERSION.tar.xz && \
    tar -xvf ccache-$CCACHE_VERSION.tar.xz && cd ccache-$CCACHE_VERSION && \
    mkdir build && cd build && \
    export LDFLAGS='-lpthread' && \
    cmake -D CMAKE_BUILD_TYPE=Release .. && \
    make -j && make install && \
    rm -rf /tmp/ccache-$CCACHE_VERSION /tmp/ccache-$CCACHE_VERSION.tar.xz

# Install six for Bazel rules.
RUN unset CFLAGS CXXFLAGS && pip3 install -v --no-cache-dir \
    six==1.15.0 absl-py==2.3.0 pyelftools==0.32 && rm -rf /tmp/*

# Install Bazel through Bazelisk, which automatically fetches the latest Bazel version.
ENV BAZELISK_VERSION 1.9.0
RUN curl -L https://github.com/bazelbuild/bazelisk/releases/download/v$BAZELISK_VERSION/bazelisk-linux-amd64 -o /usr/local/bin/bazel && \
    chmod +x /usr/local/bin/bazel

# Default build flags for various sanitizers.
ENV SANITIZER_FLAGS_address "-fsanitize=address -fsanitize-address-use-after-scope"
ENV SANITIZER_FLAGS_hwaddress "-fsanitize=hwaddress -fuse-ld=lld -Wno-unused-command-line-argument"

# Set of '-fsanitize' flags matches '-fno-sanitize-recover' + 'unsigned-integer-overflow'.
ENV SANITIZER_FLAGS_undefined "-fsanitize=array-bounds,bool,builtin,enum,function,integer-divide-by-zero,null,object-size,return,returns-nonnull-attribute,shift,signed-integer-overflow,unsigned-integer-overflow,unreachable,vla-bound,vptr -fno-sanitize-recover=array-bounds,bool,builtin,enum,function,integer-divide-by-zero,null,object-size,return,returns-nonnull-attribute,shift,signed-integer-overflow,unreachable,vla-bound,vptr"

# Don't include "function" since it is unsupported on aarch64.
ENV SANITIZER_FLAGS_undefined_aarch64 "-fsanitize=array-bounds,bool,builtin,enum,integer-divide-by-zero,null,object-size,return,returns-nonnull-attribute,shift,signed-integer-overflow,unsigned-integer-overflow,unreachable,vla-bound,vptr -fno-sanitize-recover=array-bounds,bool,builtin,enum,integer-divide-by-zero,null,object-size,return,returns-nonnull-attribute,shift,signed-integer-overflow,unreachable,vla-bound,vptr"

ENV SANITIZER_FLAGS_memory "-fsanitize=memory -fsanitize-memory-track-origins"

ENV SANITIZER_FLAGS_thread "-fsanitize=thread"

ENV SANITIZER_FLAGS_introspector "-O0 -flto -fno-inline-functions -fuse-ld=gold -Wno-unused-command-line-argument"

# Do not use any sanitizers in the coverage build.
ENV SANITIZER_FLAGS_coverage ""

# We use unsigned-integer-overflow as an additional coverage signal and have to
# suppress error messages. See https://github.com/google/oss-fuzz/issues/910.
ENV UBSAN_OPTIONS="silence_unsigned_overflow=1"

# To suppress warnings from binaries running during compilation.
ENV DFSAN_OPTIONS='warn_unimplemented=0'

# Default build flags for coverage feedback.
ENV COVERAGE_FLAGS="-fsanitize=fuzzer-no-link"

# Use '-Wno-unused-command-line-argument' to suppress "warning: -ldl: 'linker' input unused"
# messages which are treated as errors by some projects.
ENV COVERAGE_FLAGS_coverage "-fprofile-instr-generate -fcoverage-mapping -pthread -Wl,--no-as-needed -Wl,-ldl -Wl,-lm -Wno-unused-command-line-argument"

# Default sanitizer, fuzzing engine and architecture to use.
ENV SANITIZER="address"
ENV FUZZING_ENGINE="libfuzzer"
ENV ARCHITECTURE="x86_64"

# DEPRECATED - NEW CODE SHOULD NOT USE THIS. OLD CODE SHOULD STOP. Please use
# LIB_FUZZING_ENGINE instead.
# Path to fuzzing engine library to support some old users of
# LIB_FUZZING_ENGINE.
ENV LIB_FUZZING_ENGINE_DEPRECATED="/usr/lib/libFuzzingEngine.a"

# Argument passed to compiler to link against fuzzing engine.
# Defaults to the path, but is "-fsanitize=fuzzer" in libFuzzer builds.
ENV LIB_FUZZING_ENGINE="/usr/lib/libFuzzingEngine.a"

# TODO: remove after tpm2 catchup.
ENV FUZZER_LDFLAGS ""

WORKDIR $SRC

RUN git clone https://github.com/AFLplusplus/AFLplusplus.git aflplusplus && \
    cd aflplusplus && \
    git checkout daaefcddc063b356018c29027494a00bcfc3e240 && \
    wget --no-check-certificate -O oss.sh https://raw.githubusercontent.com/vanhauser-thc/binary_blobs/master/oss.sh && \
    rm -rf .git && \
    chmod 755 oss.sh

# Do precompiles before copying other scripts for better cache efficiency.
COPY precompile_afl /usr/local/bin/
RUN precompile_afl

RUN cd $SRC && \
    curl -L -O https://github.com/google/honggfuzz/archive/oss-fuzz.tar.gz && \
    mkdir honggfuzz && \
    cd honggfuzz && \
    tar -xz --strip-components=1 -f $SRC/oss-fuzz.tar.gz && \
    rm -rf examples $SRC/oss-fuzz.tar.gz


COPY precompile_honggfuzz_ubuntu_24_04 /usr/local/bin/
RUN precompile_honggfuzz_ubuntu_24_04

RUN cd $SRC && \
    git clone https://github.com/google/fuzztest && \
    cd fuzztest && \
    git checkout a37d133f714395cabc20dd930969a889495c9f53 && \
    rm -rf .git

ENV CENTIPEDE_BIN_DIR=$SRC/fuzztest/bazel-bin
COPY precompile_centipede /usr/local/bin/
RUN precompile_centipede

COPY sanitizers /usr/local/lib/sanitizers

COPY bazel_build_fuzz_tests \
    cargo \
    compile \
    compile_afl \
    compile_centipede \
    compile_honggfuzz \
    compile_fuzztests.sh \
    compile_go_fuzzer \
    compile_javascript_fuzzer \
    compile_libfuzzer \
    compile_native_go_fuzzer \
    compile_native_go_fuzzer_v2 \
    go_utils.sh \
    compile_python_fuzzer \
    debug_afl \
    # Go, JavaScript, Java, Python, Rust, and Swift installation scripts.
    install_go.sh \
    install_javascript.sh \
    install_java.sh \
    install_python.sh \
    install_ruby.sh \
    install_rust.sh \
    install_swift_ubuntu_24_04.sh \
    make_build_replayable.py \
    python_coverage_helper.py \
    replay_build.sh \
    srcmap \
    write_labels.py \
    unshallow_repos.py \
    /usr/local/bin/

# TODO: Build this as part of a multi-stage build.
ADD https://commondatastorage.googleapis.com/clusterfuzz-builds/jcc/clang-jcc /usr/local/bin/
ADD https://commondatastorage.googleapis.com/clusterfuzz-builds/jcc/clang++-jcc /usr/local/bin
ADD https://commondatastorage.googleapis.com/clusterfuzz-builds/jcc/clang-jcc2 /usr/local/bin/
ADD https://commondatastorage.googleapis.com/clusterfuzz-builds/jcc/clang++-jcc2 /usr/local/bin
RUN chmod +x /usr/local/bin/clang-jcc /usr/local/bin/clang++-jcc /usr/local/bin/clang-jcc2 /usr/local/bin/clang++-jcc2

COPY indexer /opt/indexer
COPY --from=gcr.io/oss-fuzz-base/indexer /indexer/build/indexer /opt/indexer/indexer
RUN chmod a+x /opt/indexer/indexer /opt/indexer/index_build.py

CMD ["compile"]
