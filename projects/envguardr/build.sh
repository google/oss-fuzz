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

cd "$SRC/envguardr"

npm ci
npm run build

cp -r "$SRC/envguardr" "$OUT/envguardr"

mkdir -p "$OUT/node/bin"
cp "$(command -v node)" "$OUT/node/bin/node"

"$OUT/node/bin/node" --version | grep -E '^v26\.' >/dev/null

create_jazzer_wrapper() {
  local fuzz_target="$1"
  local fuzzer_name
  fuzzer_name="$(basename -s .js "$fuzz_target")"

  cat > "$OUT/$fuzzer_name" <<EOF
#!/bin/bash
# LLVMFuzzerTestOneInput
project_dir=\$(dirname "\$0")/envguardr
node_bin=\$(dirname "\$0")/node/bin/node

exec "\$node_bin" "\$project_dir/node_modules/@jazzer.js/core/dist/cli.js" "\$project_dir/$fuzz_target" --sync \$JAZZERJS_EXTRA_ARGS -- "\$@"
EOF

  chmod +x "$OUT/$fuzzer_name"
}

create_jazzer_wrapper "fuzz/validate-env.fuzz.js"
create_jazzer_wrapper "fuzz/validate-env-custom-validators.fuzz.js"
create_jazzer_wrapper "fuzz/validate-env-schema.fuzz.js"
create_jazzer_wrapper "fuzz/validate-env-edge-cases.fuzz.js"
