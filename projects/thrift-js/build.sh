#!/bin/bash -eu
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

export ASAN_OPTIONS=detect_leaks=0

# Build and install the compiler...
# Disable other languages to save on compile time
./bootstrap.sh
./configure --enable-static --disable-shared --with-cpp=no --with-c_glib=no --with-python=no --with-py3=no --with-go=no --with-rs=no --with-java=no --with-nodejs=yes --with-dotnet=no --with-kotlin=no
make -j$(nproc)

# We only fuzz the nodejs ones for now, will do the base JS ones later in a followup
# TODO: Do this
pushd lib/nodejs
make stubs
make install

# This leaves the directory so the install is in thrift/
npm install --save-dev @jazzer.js/core

# Copy source code into the $OUT directory
if [ ! -d $OUT/thrift ]; then
    cp -r lib/thrift $OUT
    cp -r test/fuzz $OUT
    cp -r $SRC/node_modules $OUT
fi

pushd test/fuzz

# Copied from https://github.com/google/oss-fuzz/blob/master/infra/base-images/base-builder/compile_javascript_fuzzer
# Need to make changes to how we set up the paths
compile_javascript_fuzzer() {
    # Path the fuzz target source file relative to the project's root.
    fuzz_target=$1
    # Arguments to pass to Jazzer.js
    jazzerjs_args=${@:2}

    fuzzer_basename=$(basename -s .js $fuzz_target)

    # Create an execution wrapper that executes Jazzer.js with the correct arguments.
    echo "#!/bin/bash
# LLVMFuzzerTestOneInput so that the wrapper script is recognized as a fuzz target for 'check_build'.
thrift/node_modules/@jazzer.js/core/dist/cli.js thrift/lib/nodejs/test/fuzz/$fuzz_target $jazzerjs_args \$JAZZERJS_EXTRA_ARGS -- \$@" > $OUT/$fuzzer_basename

    chmod +x $OUT/$fuzzer_basename
}

compile_javascript_fuzzer fuzz_parse_TBinaryProtocol.js --sync
compile_javascript_fuzzer fuzz_parse_TCompactProtocol.js --sync
compile_javascript_fuzzer fuzz_parse_TJSONProtocol.js --sync
compile_javascript_fuzzer fuzz_roundtrip_TBinaryProtocol.js --sync
compile_javascript_fuzzer fuzz_roundtrip_TCompactProtocol.js --sync
compile_javascript_fuzzer fuzz_roundtrip_TJSONProtocol.js --sync

popd
popd
