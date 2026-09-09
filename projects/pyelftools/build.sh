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

pip3 install $SRC/pyelftools
pip3 install atheris

for fuzzer in $(find $SRC -name '*_fuzzer.py'); do
    fuzzer_basename=$(basename -s .py $fuzzer)
    fuzzer_package=${fuzzer_basename}.pkg

    if [ "${SANITIZER:-address}" = "coverage" ]; then
        cp "$fuzzer" "$OUT/${fuzzer_basename}.py"
        cat > "$OUT/${fuzzer_basename}" <<EOF
#!/bin/sh
this_dir=\$(dirname "\$0")
python3 -m pip install -q atheris || true
ASAN_OPTIONS=\${ASAN_OPTIONS:-}:symbolize=1:external_symbolizer_path=\$this_dir/llvm-symbolizer:detect_leaks=0 \\
python3 "\$this_dir/${fuzzer_basename}.py" "\$@"
EOF
        chmod +x "$OUT/${fuzzer_basename}"
    else
        pyinstaller \
            --distpath "$OUT" \
            --onefile \
            --name "$fuzzer_package" \
            "$fuzzer"

        cat > "$OUT/${fuzzer_basename}" <<EOF
#!/bin/sh
this_dir=\$(dirname "\$0")
ASAN_OPTIONS=\${ASAN_OPTIONS:-}:symbolize=1:external_symbolizer_path=\$this_dir/llvm-symbolizer:detect_leaks=0 \
"\$this_dir/$fuzzer_package" "\$@"
EOF
        chmod +x "$OUT/${fuzzer_basename}"
    fi

done

for base in elf_sections_fuzzer dwarf_info_fuzzer elf_hash_fuzzer elf_arm_fuzzer; do
  if [ -f "$SRC/${base}.dict" ]; then cp "$SRC/${base}.dict" "$OUT/${base}.dict"; fi
  if [ -f "$SRC/${base}.options" ]; then cp "$SRC/${base}.options" "$OUT/${base}.options"; fi
done
