#!/bin/bash -eu
# Copyright 2022 Google Inc.
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

# Without this hack, we get /usr/bin/env: 'python3': No such file or directory.
# Bazel somehow clears the env variable PATH, so python3 must be in system's path.
cp /usr/local/bin/python3 /usr/bin/

# some third party fuzz target not compiling
rm -Rf third_party/utf8_range/fuzz/

# Avoid infinite recursion by rsync on symlinks on coverage build
sed -i -e 's/rsync/baserm=`bazel info execution_root`; rm \$baserm\/external\/com_google_protobuf\/bazel-protobuf\nrsync/' /usr/local/bin/bazel_build_fuzz_tests

bazel_build_fuzz_tests

mkdir /tmp/corpus
find . -name "*.proto" | while read i; do cp $i /tmp/corpus/; done
cd /tmp
zip -r $OUT/fuzz_compiler_parser_seed_corpus.zip corpus
