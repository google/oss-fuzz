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

export ASAN_OPTIONS="${ASAN_OPTIONS:+$ASAN_OPTIONS:}detect_leaks=0"
cd "$SRC/thrift"

./bootstrap.sh
./configure --enable-static --disable-shared --with-cpp=no --with-c_glib=no --with-python=no --with-py3=no --with-go=no --with-rs=no --with-java=no --with-nodejs=no --with-dotnet=no --with-kotlin=no --with-ruby=yes
make -C compiler/cpp -j"$(nproc)" all

make -C lib/rb/test/fuzz fuzz-prepare
make -C lib/rb/test/fuzz fuzz-build-ext \
  FUZZ_CFLAGS="-fsanitize=address,fuzzer-no-link -fno-omit-frame-pointer -fno-common -fPIC -g -fno-builtin-strlcpy"

verify_accelerated() {
  local error_message="$1"
  local gem_home="$2"
  local gem_path="$3"
  local asan_path

  asan_path=$(GEM_HOME="$gem_home" GEM_PATH="$gem_path" ruby -e 'require "ruzzy"; print Ruzzy::ASAN_PATH')
  GEM_HOME="$gem_home" \
  GEM_PATH="$gem_path" \
  LD_PRELOAD="$asan_path" \
  RUBYLIB="lib:ext" \
  ruby -e "require 'ruzzy'; require 'thrift'; abort('$error_message') unless Thrift::BinaryProtocolAcceleratedFactory.new.to_s == 'binary-accel'"
}

pushd lib/rb
verify_accelerated "thrift_native did not load" "${GEM_HOME:-/out/fuzz-gem}" "${GEM_PATH:-/install/ruzzy}"
popd

mkdir -p "$OUT/thrift/lib/rb"
cp -R lib/rb/lib "$OUT/thrift/lib/rb/"
cp -R lib/rb/ext "$OUT/thrift/lib/rb/"
cp -R lib/rb/test "$OUT/thrift/lib/rb/"

mkdir -p "$OUT/thrift-rb-gems"
rsync -a \
  --exclude 'cache/' \
  --exclude 'doc/' \
  /install/ruzzy/ "$OUT/thrift-rb-gems/"

pushd "$OUT/thrift/lib/rb"
verify_accelerated "packaged thrift_native did not load" "$OUT/thrift-rb-gems" "$OUT/thrift-rb-gems"
popd

emit_wrapper() {
  local tracer="$1"
  local fuzzer_name="${tracer%.rb}"

  cat > "$OUT/$fuzzer_name" <<EOF
#!/bin/bash
# LLVMFuzzerTestOneInput for fuzzer detection.
this_dir=\$(dirname "\$0")
export GEM_HOME="\$this_dir/thrift-rb-gems"
export GEM_PATH="\$this_dir/thrift-rb-gems"
ASAN_OPTIONS="\${ASAN_OPTIONS:+\$ASAN_OPTIONS:}allocator_may_return_null=1:detect_leaks=0:use_sigaltstack=0" \
LD_PRELOAD=\$(ruby -e 'require "ruzzy"; print Ruzzy::ASAN_PATH') \
exec ruby "\$this_dir/thrift/lib/rb/test/fuzz/$tracer" "\$@"
EOF

  chmod +x "$OUT/$fuzzer_name"
}

while IFS= read -r tracer; do
  emit_wrapper "$tracer"
done < <(
  find lib/rb/test/fuzz -maxdepth 1 -type f -name 'fuzz_*.rb' \
    ! -name '*_harness.rb' \
    ! -name 'fuzz_common.rb' \
    ! -name 'fuzz_tracer.rb' \
    -printf '%f\n' | sort
)
