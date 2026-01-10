#!/bin/bash -eu
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

# Install jazzer.js for fuzzing
npm install --save-dev @jazzer.js/core

# Create the directory structure expected by the fuzzers
# Fuzzers use require("../../lib/thrift") so they need to be at lib/nodejs/test/fuzz/
# and the thrift library at lib/nodejs/lib/thrift/
mkdir -p $OUT/thrift/lib/nodejs/lib
mkdir -p $OUT/thrift/lib/nodejs/test

# Copy files to match the expected structure (we're in lib/nodejs/)
cp -r lib/thrift $OUT/thrift/lib/nodejs/lib/
cp -r test/fuzz $OUT/thrift/lib/nodejs/test/

# node_modules may be in current dir or have been hoisted - find and copy it
if [ -d "node_modules" ]; then
    cp -r node_modules $OUT/thrift/
elif [ -d "../../node_modules" ]; then
    cp -r ../../node_modules $OUT/thrift/
else
    echo "ERROR: Could not find node_modules"
    find /src -name "node_modules" -type d 2>/dev/null | head -5
    exit 1
fi

pushd test/fuzz

compile_javascript_fuzzer() {
    fuzz_target=$1
    jazzerjs_args=${@:2}
    fuzzer_basename=$(basename -s .js $fuzz_target)

    # Use this_dir for portability (works in check_build which copies to /tmp)
    echo "#!/bin/bash
# LLVMFuzzerTestOneInput so that the wrapper script is recognized as a fuzz target for 'check_build'.
this_dir=\$(dirname \"\$0\")
\$this_dir/thrift/node_modules/@jazzer.js/core/dist/cli.js \$this_dir/thrift/lib/nodejs/test/fuzz/$fuzz_target $jazzerjs_args \$JAZZERJS_EXTRA_ARGS -- \"\$@\"" > $OUT/$fuzzer_basename

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
