#!/usr/bin/env python3
"""OSS-Fuzz target: signed-envelope verification must never crash.

The corpus is a set of JSON envelopes (valid and mutated). This target parses
the fuzzed bytes as an envelope and calls ``verify_envelope``. A clean rejection
(ValueError / TypeError / KeyError) is expected; any other exception is a crash
and is reported by OSS-Fuzz.
"""

import atheris
import json
import sys

with atheris.instrument_imports():
    from kinegrant.crypto import verify_envelope


def TestOneInput(data: bytes) -> None:
    try:
        envelope = json.loads(data)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return
    if not isinstance(envelope, dict):
        return
    try:
        verify_envelope(envelope)
    except (ValueError, TypeError, KeyError):
        return


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
