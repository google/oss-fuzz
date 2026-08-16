#!/usr/bin/env python3
"""OSS-Fuzz target: the action gate must fail closed, never crash.

Feeds fuzzed JSON as a capability envelope to ``ActionGate.authorize`` against a
fixed request. A clean rejection (PermissionError / ValueError / TypeError /
KeyError) is expected; anything else is a crash.
"""

import atheris
import json
import sys

with atheris.instrument_imports():
    from kinegrant.gate import ActionGate
    from kinegrant.models import ActionRequest


REQUEST = ActionRequest(
    "urn:kinegrant:ossfuzz:request",
    "urn:kinegrant:ossfuzz:agent",
    "urn:kinegrant:ossfuzz:target",
    "open",
    "delivery",
)
GATE = ActionGate(trusted_issuers=set())  # trust nobody: fail closed


def TestOneInput(data: bytes) -> None:
    try:
        capability = json.loads(data)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return
    if not isinstance(capability, dict):
        return
    try:
        GATE.authorize(capability, REQUEST)
    except (PermissionError, ValueError, TypeError, KeyError):
        return


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
