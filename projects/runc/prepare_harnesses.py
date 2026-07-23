#!/usr/bin/env python3
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

from pathlib import Path

FUZZERS = Path("/src/cncf-fuzzing/projects/runc")

def replace_once(path: Path, old: str, new: str) -> None:
    source = path.read_text()
    if old not in source:
        raise RuntimeError(
            f"Expected content not found in {path}: {old!r}"
        )
    path.write_text(source.replace(old, new, 1))

def adapt_utils_fuzzer() -> None:
    harness = FUZZERS / "libcontainer_utils_fuzzer.go"
    replace_once(
        harness,
        'fuzz "github.com/AdaLogics/go-fuzz-headers"',
        'fuzz "github.com/AdaLogics/go-fuzz-headers"\n'
        '\t"github.com/opencontainers/runc/internal/pathrs"',
    )
    replace_once(
        harness,
        "_ = stripRoot(root, path)",
        "_ = pathrs.LexicallyStripRoot(root, path)",
    )

def adapt_fs2_fuzzer() -> None:
    replace_once(
        FUZZERS / "fs2_fuzzer.go",
        '"github.com/opencontainers/runc/libcontainer/cgroups"',
        '"github.com/opencontainers/cgroups"',
    )

def adapt_specconv_fuzzer() -> None:
    harness = FUZZERS / "specconv_fuzzer.go"
    replace_once(
        harness,
        '"github.com/opencontainers/runc/libcontainer/cgroups/systemd"',
        '"github.com/opencontainers/cgroups/systemd"',
    )
    replace_once(
        harness,
        '"github.com/opencontainers/runc/libcontainer/configs"',
        '"github.com/opencontainers/cgroups"',
    )
    replace_once(
        harness,
        "config := &configs.Resources{}",
        "config := &cgroups.Resources{}",
    )

def main() -> None:
    adapt_utils_fuzzer()
    adapt_fs2_fuzzer()
    adapt_specconv_fuzzer()

if __name__ == "__main__":
    main()
