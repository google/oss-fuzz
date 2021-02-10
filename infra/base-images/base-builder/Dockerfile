# Copyright 2016 Google Inc.
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

FROM gcr.io/oss-fuzz-base/base-clang

RUN dpkg --add-architecture i386 && \
    apt-get update && \
    apt-get install -y software-properties-common && \
    add-apt-repository ppa:git-core/ppa && \
    apt-get update && \
    apt-get install -y \
        binutils-dev \
        build-essential \
        curl \
        git \
        jq \
        libc6-dev-i386 \
        patchelf \
        subversion \
        zip

# Build and install latest Python 3 (3.8.3).
ENV PYTHON_VERSION 3.8.3
RUN export PYTHON_DEPS="\
        zlib1g-dev \
        libncurses5-dev \
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
    make -j install && \
    ldconfig && \
    ln -s /usr/bin/python3 /usr/bin/python && \
    cd .. && \
    rm -r /tmp/Python-$PYTHON_VERSION.tar.xz /tmp/Python-$PYTHON_VERSION && \
    apt-get remove -y $PYTHON_DEPS  # https://github.com/google/oss-fuzz/issues/3888

# Install latest atheris for python fuzzing, pyinstaller for fuzzer packaging,
# six for Bazel rules.
RUN unset CFLAGS CXXFLAGS && pip3 install -v \
    atheris pyinstaller==4.1 six==1.15.0

# Download and install the latest stable Go.
RUN cd /tmp && \
    curl -O https://storage.googleapis.com/golang/getgo/installer_linux && \
    chmod +x ./installer_linux && \
    SHELL="bash" ./installer_linux && \
    rm -rf ./installer_linux

# Set up Golang environment variables (copied from /root/.bash_profile).
ENV GOPATH /root/go

# /root/.go/bin is for the standard Go binaries (i.e. go, gofmt, etc).
# $GOPATH/bin is for the binaries from the dependencies installed via "go get".
ENV PATH $PATH:/root/.go/bin:$GOPATH/bin

# Uses golang 1.14+ cmd/compile's native libfuzzer instrumentation.
RUN go get -u github.com/mdempsky/go114-fuzz-build && \
    ln -s $GOPATH/bin/go114-fuzz-build $GOPATH/bin/go-fuzz

# Install Rust and cargo-fuzz for libFuzzer instrumentation.
ENV CARGO_HOME=/rust
ENV RUSTUP_HOME=/rust/rustup
ENV PATH=$PATH:/rust/bin
RUN curl https://sh.rustup.rs | sh -s -- -y --default-toolchain=nightly --profile=minimal
RUN cargo install cargo-fuzz
# Needed to recompile rust std library for MSAN
RUN rustup component add rust-src --toolchain nightly

# Install Bazel through Bazelisk, which automatically fetches the latest Bazel version.
ENV BAZELISK_VERSION 1.7.4
RUN curl -L https://github.com/bazelbuild/bazelisk/releases/download/v$BAZELISK_VERSION/bazelisk-linux-amd64 -o /usr/local/bin/bazel && \
    chmod +x /usr/local/bin/bazel

# Install OpenJDK 15 and trim its size by removing unused components.
ENV JAVA_HOME=/usr/lib/jvm/java-15-openjdk-amd64
ENV JVM_LD_LIBRARY_PATH=$JAVA_HOME/lib/server
ENV PATH=$PATH:$JAVA_HOME/bin
RUN cd /tmp && \
    curl -L -O https://download.java.net/java/GA/jdk15.0.2/0d1cfde4252546c6931946de8db48ee2/7/GPL/openjdk-15.0.2_linux-x64_bin.tar.gz && \
    mkdir -p $JAVA_HOME && \
    tar -xzv --strip-components=1 -f openjdk-15.0.2_linux-x64_bin.tar.gz --directory $JAVA_HOME && \
    rm -f openjdk-15.0.2_linux-x64_bin.tar.gz && \
    rm -rf $JAVA_HOME/jmods $JAVA_HOME/lib/src.zip

# Install the latest Jazzer in $OUT.
# jazzer_api_deploy.jar is required only at build-time, the agent and the
# drivers are copied to $OUT as they need to be present on the runners.
ENV JAZZER_API_PATH "/usr/local/lib/jazzer_api_deploy.jar"
RUN cd $SRC/ && \
    git clone --depth=1 https://github.com/CodeIntelligenceTesting/jazzer && \
    cd jazzer && \
    bazel build --java_runtime_version=localjdk_15 -c opt --cxxopt="-stdlib=libc++" --linkopt=-lc++ \
        //agent:jazzer_agent_deploy.jar //driver:jazzer_driver //driver:jazzer_driver_asan //agent:jazzer_api_deploy.jar && \
    cp bazel-bin/agent/jazzer_agent_deploy.jar bazel-bin/driver/jazzer_driver bazel-bin/driver/jazzer_driver_asan /usr/local/bin/ && \
    cp bazel-bin/agent/jazzer_api_deploy.jar $JAZZER_API_PATH && \
    rm -rf ~/.cache/bazel ~/.cache/bazelisk && \
    rm -rf $SRC/jazzer

# Default build flags for various sanitizers.
ENV SANITIZER_FLAGS_address "-fsanitize=address -fsanitize-address-use-after-scope"

# Set of '-fsanitize' flags matches '-fno-sanitize-recover' + 'unsigned-integer-overflow'.
ENV SANITIZER_FLAGS_undefined "-fsanitize=array-bounds,bool,builtin,enum,float-divide-by-zero,function,integer-divide-by-zero,null,object-size,return,returns-nonnull-attribute,shift,signed-integer-overflow,unsigned-integer-overflow,unreachable,vla-bound,vptr -fno-sanitize-recover=array-bounds,bool,builtin,enum,float-divide-by-zero,function,integer-divide-by-zero,null,object-size,return,returns-nonnull-attribute,shift,signed-integer-overflow,unreachable,vla-bound,vptr"

ENV SANITIZER_FLAGS_memory "-fsanitize=memory -fsanitize-memory-track-origins"

ENV SANITIZER_FLAGS_dataflow "-fsanitize=dataflow"

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

# Coverage isntrumentation flags for dataflow builds.
ENV COVERAGE_FLAGS_dataflow="-fsanitize-coverage=trace-pc-guard,pc-table,bb,trace-cmp"

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

ENV PRECOMPILED_DIR="/usr/lib/precompiled"
RUN mkdir $PRECOMPILED_DIR

WORKDIR $SRC

# TODO: switch to -b stable once we can.
RUN git clone https://github.com/AFLplusplus/AFLplusplus.git aflplusplus && \
    cd aflplusplus && \
    git checkout aeb7d7048371cd91ab9280c3958f1c35e5d5e758

RUN cd $SRC && \
    curl -L -O https://github.com/google/honggfuzz/archive/oss-fuzz.tar.gz && \
    mkdir honggfuzz && \
    cd honggfuzz && \
    tar -xzv --strip-components=1 -f $SRC/oss-fuzz.tar.gz && \
    rm -rf examples $SRC/oss-fuzz.tar.gz

COPY compile compile_afl compile_dataflow compile_libfuzzer compile_honggfuzz \
    compile_go_fuzzer precompile_honggfuzz srcmap write_labels.py /usr/local/bin/

COPY detect_repo.py /opt/cifuzz/
COPY ossfuzz_coverage_runner.go $GOPATH

RUN precompile_honggfuzz

CMD ["compile"]
