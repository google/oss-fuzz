#!/bin/bash -eu

################################################################################
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
################################################################################

python3 -m pip install .

for target in parser roundtrip; do
  pyinstaller --distpath "$OUT" --onefile \
    --name "yaraast_${target}_fuzzer.pkg" "fuzz/run_${target}_fuzz.py"
  cat > "$OUT/yaraast_${target}_fuzzer" <<EOF
#!/bin/sh
exec "\$(dirname "\$0")/yaraast_${target}_fuzzer.pkg" "\$@"
EOF
  chmod +x "$OUT/yaraast_${target}_fuzzer"
done
