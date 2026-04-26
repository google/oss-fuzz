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
"""Atheris harness for bumble.att.ATT_PDU.from_bytes.

ATT PDUs are remote-peer-controlled on every GATT client connection. Prior bugs
in this parser (e.g. empty-PDU IndexError fixed in PR #912) caused host crashes.
"""
import sys
import atheris

with atheris.instrument_imports():
    from bumble import att

_BENIGN = (ValueError, IndexError, KeyError, TypeError,
           NotImplementedError, UnicodeDecodeError, OverflowError,
           __import__("struct").error)


def TestOneInput(data: bytes) -> None:
    try:
        att.ATT_PDU.from_bytes(data)
    except _BENIGN:
        pass


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
