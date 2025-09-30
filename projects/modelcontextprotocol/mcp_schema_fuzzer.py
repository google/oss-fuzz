#!/usr/bin/env python3
"""
Copyright 2025 The OSS-Fuzz project authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
import atheris
import sys
import io
import os
import json
from typing import Optional

# We depend on jsonschema for validation; installed in Dockerfile.
try:
    import jsonschema
    from jsonschema.validators import validator_for
    from jsonschema import FormatChecker
except Exception as e:
    # If jsonschema isn't available, raise early during local runs.
    raise


def _load_schema() -> Optional[dict]:
    # Priority:
    # 1) MCP_SCHEMA_PATH env var
    # 2) schema.json adjacent to the executable (set by build.sh wrapper)
    # 3) schema in the repo (useful for local runs)
    candidates = []

    env_path = os.environ.get("MCP_SCHEMA_PATH")
    if env_path:
        candidates.append(env_path)

    # Adjacent to PyInstaller dist binary
    exe_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
    candidates.append(os.path.join(exe_dir, "schema.json"))

    # Local repo fallback for manual testing
    repo_schema_dir = os.path.join(os.environ.get("SRC", ""), "modelcontextprotocol", "schema")
    if os.path.isdir(repo_schema_dir):
        # Try to pick the latest subdir if present
        try:
            subdirs = [os.path.join(repo_schema_dir, d) for d in os.listdir(repo_schema_dir)]
            subdirs = [d for d in subdirs if os.path.isdir(d)]
            subdirs.sort()
            if subdirs:
                candidates.append(os.path.join(subdirs[-1], "schema.json"))
        except Exception:
            pass

    for path in candidates:
        try:
            if path and os.path.isfile(path):
                with open(path, "rb") as f:
                    return json.load(f)
        except Exception:
            # Ignore and try next candidate
            continue
    return None


SCHEMA = _load_schema()
VALIDATOR = None
if SCHEMA is not None:
    try:
        ValidatorClass = validator_for(SCHEMA)
        ValidatorClass.check_schema(SCHEMA)
        VALIDATOR = ValidatorClass(SCHEMA, format_checker=FormatChecker())
    except Exception:
        # If schema is invalid or unsupported, leave VALIDATOR as None.
        VALIDATOR = None


def TestOneInput(data: bytes) -> None:  # LLVMFuzzerTestOneInput name for libFuzzer
    # Limit excessively large inputs to keep JSON decoding tractable
    if len(data) > 1_000_000:
        return

    # Try UTF-8 first; if it fails, attempt latin-1 which maps bytes 1:1.
    try:
        s = data.decode("utf-8")
    except UnicodeDecodeError:
        try:
            s = data.decode("latin-1")
        except Exception:
            return

    # Attempt to parse JSON
    try:
        obj = json.loads(s)
    except Exception:
        return

    # If we have a compiled validator, validate the object
    if VALIDATOR is not None:
        try:
            VALIDATOR.validate(obj)
        except Exception:
            # We expect many validation failures; only crashes are interesting
            pass


def main():
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
