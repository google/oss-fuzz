#!/usr/bin/env python3
# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
"""BT advertising/EIR data-type parser harness.

Covers 20+ data_types classes that share from_bytes() signature. An attacker
nearby can inject arbitrary bytes into any of these via advertising packets.
"""
import sys
import atheris

with atheris.instrument_imports():
    from bumble import data_types

_TARGETS = []
for _name in (
    "CompleteListOf16BitServiceUUIDs", "CompleteListOf32BitServiceUUIDs",
    "CompleteListOf128BitServiceUUIDs", "Flags", "ManufacturerSpecificData",
    "CompleteLocalName", "ShortenedLocalName", "TxPowerLevel", "ClassOfDevice",
    "PeripheralConnectionIntervalRange", "ServiceData16BitUUID",
    "ServiceData32BitUUID", "ServiceData128BitUUID",
    "PublicTargetAddress", "Appearance", "AdvertisingInterval",
    "LeBluetoothDeviceAddress", "URI", "BroadcastCode",
):
    _cls = getattr(data_types, _name, None)
    if _cls is not None and hasattr(_cls, "from_bytes"):
        _TARGETS.append(_cls.from_bytes)

_BENIGN = (ValueError, IndexError, KeyError, TypeError,
           NotImplementedError, UnicodeDecodeError, OverflowError,
           __import__("struct").error)


def TestOneInput(data: bytes) -> None:
    if len(data) < 1 or not _TARGETS:
        return
    target = _TARGETS[data[0] % len(_TARGETS)]
    try:
        target(data[1:])
    except _BENIGN:
        pass


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
