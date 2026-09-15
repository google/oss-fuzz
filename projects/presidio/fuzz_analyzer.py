#!/usr/bin/python3
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
"""Fuzzer for presidio-analyzer AnalyzerEngine.analyze()."""

import sys
import atheris

with atheris.instrument_imports():
    from presidio_analyzer import AnalyzerEngine

# Initialize once to avoid repeated model loading.
engine = AnalyzerEngine()

ENTITY_TYPES = [
    "PHONE_NUMBER",
    "CREDIT_CARD",
    "EMAIL_ADDRESS",
    "IBAN_CODE",
    "IP_ADDRESS",
    "PERSON",
    "LOCATION",
    "DATE_TIME",
    "NRP",
    "MEDICAL_LICENSE",
    "URL",
    "US_SSN",
    "US_BANK_NUMBER",
    "US_DRIVER_LICENSE",
    "US_PASSPORT",
    "US_ITIN",
]


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    text = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 2048))
    if not text:
        return

    # Optionally restrict to a subset of entity types.
    use_subset = fdp.ConsumeBool()
    entities = None
    if use_subset:
        count = fdp.ConsumeIntInRange(1, len(ENTITY_TYPES))
        entities = [ENTITY_TYPES[fdp.ConsumeIntInRange(0, len(ENTITY_TYPES) - 1)]
                    for _ in range(count)]

    try:
        results = engine.analyze(
            text=text,
            language="en",
            entities=entities,
        )
    except (ValueError, RecursionError):
        return


def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
