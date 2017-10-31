#!/bin/bash -eu
# Copyright 2017 Google Inc.
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

DISABLED_WARNINGS='-Wno-everything'

# Inject additional C/CXXFLAGS
cat <<EOF > /usr/local/bin/cmake
#!/bin/sh
/usr/bin/cmake \\
  -DCMAKE_C_FLAGS="\$CFLAGS $DISABLED_WARNINGS" \\
  -DCMAKE_CXX_FLAGS="\$CXXFLAGS $DISABLED_WARNINGS" \\
  "\$@"
EOF

chmod +x /usr/local/bin/cmake

./build.sh --test-build --static --embed-icu --cc="$(which clang)" --cxx="$(which clang++)" -j -v -y
cp out/Test/ch $OUT
