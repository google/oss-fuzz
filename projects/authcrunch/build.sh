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

cd "$SRC/authcrunch"
export GOMAXPROCS=2
export GOFLAGS="${GOFLAGS:-} -mod=mod -p=2"

# Use the foundation versions selected by the distribution, with Go's module
# authentication intact. Writable copies permit native-fuzzer conversion and
# retain source for coverage and debugging. Do not move upstream release tags.
go mod download
go mod verify
for name in caddy-security go-authcrunch; do
  module="github.com/greenpau/$name"
  source_dir=$(go list -m -f '{{.Dir}}' "$module")
  target_dir="$SRC/authcrunch-foundation/$name"
  mkdir -p "$target_dir"
  cp -a "$source_dir/." "$target_dir/"
  chmod -R u+w "$target_dir"
done

# Build each target from its owning module so the native coverage helper can
# identify the module's sources. Bind Caddy Security to the selected foundation.
go -C "$SRC/authcrunch-foundation/caddy-security" mod edit \
  "-replace=github.com/greenpau/go-authcrunch=$SRC/authcrunch-foundation/go-authcrunch"
for name in caddy-security go-authcrunch; do
  go -C "$SRC/authcrunch-foundation/$name" mod download
  go -C "$SRC/authcrunch-foundation/$name" mod verify
done

# F.Add seeds are ignored by the native-to-libFuzzer adapter. Convert explicit
# Go-format seed inputs with OSS-Fuzz's own converter, including argument framing.
python3 - <<'PY'
import json
import os
import re
from pathlib import Path

src = Path(os.environ["SRC"])
work = Path(os.environ["WORK"])
targets = json.loads((src / "fuzzers.json").read_text())

# The v2 address adapter promotes every test file in a target directory into
# production Go files. Preserve external-package tests outside that directory
# to avoid mixing, for example, package acl and package acl_test. No target or
# production code is removed, and native coverage builds keep all test files.
if os.environ["SANITIZER"] != "coverage":
    for target in targets:
        relative = target["package"].removeprefix("github.com/greenpau/")
        directory = src / "authcrunch-foundation" / relative
        for test_file in directory.glob("*_test.go"):
            if re.search(r"(?m)^package \w+_test\b", test_file.read_text()):
                backup = src / "authcrunch-external-tests" / test_file.relative_to(src)
                backup.parent.mkdir(parents=True, exist_ok=True)
                test_file.rename(backup)

with (work / "authcrunch-targets.tsv").open("w") as manifest:
    for target in targets:
        name = target["name"]
        directory = work / "authcrunch-seeds" / name
        directory.mkdir(parents=True, exist_ok=True)
        for index, seed in enumerate(target["seeds"]):
            assert len(seed) == len(target["types"])
            lines = ["go test fuzz v1"]
            for kind, value in zip(target["types"], seed):
                assert kind in ("string", "[]byte")
                lines.append(f"{kind}({json.dumps(value, ensure_ascii=True)})")
            (directory / str(index)).write_text("\n".join(lines) + "\n")
        manifest.write(f'{target["package"]}\t{target["function"]}\t{name}\n')
PY

while IFS=$'\t' read -r package function name; do
  case "$package" in
    github.com/greenpau/caddy-security*)
      cd "$SRC/authcrunch-foundation/caddy-security" ;;
    github.com/greenpau/go-authcrunch/*)
      cd "$SRC/authcrunch-foundation/go-authcrunch" ;;
    *) echo "Unexpected fuzz package: $package" >&2; exit 1 ;;
  esac
  compile_native_go_fuzzer_v2 "$package" "$function" "$name"
  # The upstream helper can return success when a function was not found.
  test -s "$OUT/$name"
  addStdLibCorpusToFuzzer \
    -dir "$WORK/authcrunch-seeds/$name" -fuzzer_name "$name"
done < "$WORK/authcrunch-targets.tsv"
