#!/usr/bin/env python3
# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
"""SDP DataElement + SDP_PDU parser harness.

Targets the nested-SEQUENCE recursion class exposed by the depth-limit fix.
"""
import sys
import atheris

with atheris.instrument_imports():
    from bumble import sdp

_BENIGN = (ValueError, IndexError, KeyError, TypeError,
           NotImplementedError, UnicodeDecodeError, OverflowError,
           __import__("struct").error)


def TestOneInput(data: bytes) -> None:
    if len(data) < 1:
        return
    picker = data[0] & 1
    payload = data[1:]
    try:
        if picker == 0:
            sdp.DataElement.from_bytes(payload)
        else:
            sdp.SDP_PDU.from_bytes(payload)
    except _BENIGN:
        pass


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
