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
MAINTAINER mike.aizatsky@gmail.com
RUN apt-get install -y git \
    subversion \
    jq \
    python3 \
    zip \
    make \
    libunwind8-dev \
    binutils-dev \
    libblocksruntime-dev \
    libc6-dev-i386

# Download and install the latest stable Go.
ADD https://storage.googleapis.com/golang/getgo/installer_linux $SRC/
RUN chmod +x $SRC/installer_linux && \
    SHELL="bash" $SRC/installer_linux && \
    rm $SRC/installer_linux

# Set up Golang environment variables (copied from /root/.bash_profile).
ENV GOPATH /root/go

# /root/.go/bin is for the standard Go binaries (i.e. go, gofmt, etc).
# $GOPATH/bin is for the binaries from the dependencies installed via "go get".
ENV PATH $PATH:/root/.go/bin:$GOPATH/bin

# Dependency of go-fuzz.
RUN go get golang.org/x/tools/go/packages

# go-fuzz-build is the tool that instruments Go files.
RUN go get github.com/dvyukov/go-fuzz/go-fuzz-build

# Default build flags for various sanitizers.
ENV SANITIZER_FLAGS_address "-fsanitize=address -fsanitize-address-use-after-scope"

# Set of '-fsanitize' flags matches '-fno-sanitize-recover' + 'unsigned-integer-overflow'.
ENV SANITIZER_FLAGS_undefined "-fsanitize=bool,array-bounds,float-divide-by-zero,function,integer-divide-by-zero,return,shift,signed-integer-overflow,unsigned-integer-overflow,vla-bound,vptr -fno-sanitize-recover=bool,array-bounds,float-divide-by-zero,function,integer-divide-by-zero,return,shift,signed-integer-overflow,vla-bound,vptr"

ENV SANITIZER_FLAGS_memory "-fsanitize=memory -fsanitize-memory-track-origins"

ENV SANITIZER_FLAGS_dataflow "-fsanitize=dataflow"

# Do not use any sanitizers in the coverage build.
ENV SANITIZER_FLAGS_coverage ""

# We use unsigned-integer-overflow as an additional coverage signal and have to
# suppress error messages. See https://github.com/google/oss-fuzz/issues/910.
ENV UBSAN_OPTIONS="silence_unsigned_overflow=1"

# Default build flags for coverage feedback.
ENV COVERAGE_FLAGS="-fsanitize=fuzzer-no-link"

# Use '-Wno-unused-command-line-argument' to suppress "warning: -ldl: 'linker' input unused"
# messages which are treated as errors by some projects.
ENV COVERAGE_FLAGS_coverage "-fprofile-instr-generate -fcoverage-mapping -pthread -Wl,--no-as-needed -Wl,-ldl -Wl,-lm -Wno-unused-command-line-argument"

# Coverage isntrumentation flags for dataflow builds.
ENV COVERAGE_FLAGS_dataflow="-fsanitize-coverage=trace-pc-guard,pc-table,func,trace-cmp"

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

RUN git clone -b stable https://github.com/google/AFL.git afl

ADD https://github.com/google/honggfuzz/archive/oss-fuzz.tar.gz $SRC/
RUN mkdir honggfuzz && \
    cd honggfuzz && \
    tar -xzv --strip-components=1 -f $SRC/oss-fuzz.tar.gz && \
    rm -rf $SRC/oss-fuzz.tar.gz

COPY compile compile_afl compile_dataflow compile_libfuzzer compile_honggfuzz \
    srcmap write_labels.py /usr/local/bin/

CMD ["compile"]
