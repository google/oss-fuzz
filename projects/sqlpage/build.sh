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

cd "$SRC/sqlpage"
cargo fuzz build -O --debug-assertions sql_file
cp fuzz/target/x86_64-unknown-linux-gnu/release/sql_file "$OUT/"

# Reuse the regression suite, including native and ODBC modes for every dialect.
python3 - <<'PY'
import os
from pathlib import Path
from zipfile import ZipFile

with ZipFile(Path(os.environ["OUT"]) / "sql_file_seed_corpus.zip", "w") as corpus:
    for index, source in enumerate(sorted(Path("tests/sql_test_files").rglob("*.sql"))):
        for selector in range(16):
            corpus.writestr(f"{index}-{selector}", bytes([selector]) + source.read_bytes())
PY

cp "$SRC/sql_file.dict" "$SRC/sql_file.options" "$OUT/"
