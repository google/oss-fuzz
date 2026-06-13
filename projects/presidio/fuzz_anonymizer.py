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
"""Fuzzer for presidio-anonymizer AnonymizerEngine.anonymize()."""

import sys
import atheris

with atheris.instrument_imports():
    from presidio_anonymizer import AnonymizerEngine
    from presidio_anonymizer.entities import RecognizerResult, OperatorConfig

engine = AnonymizerEngine()

ENTITY_TYPES = [
    "PHONE_NUMBER",
    "CREDIT_CARD",
    "EMAIL_ADDRESS",
    "PERSON",
    "LOCATION",
    "DATE_TIME",
    "US_SSN",
    "IP_ADDRESS",
    "URL",
]

OPERATORS = ["replace", "redact", "hash", "mask"]


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    text = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 2048))
    if not text or len(text) < 2:
        return

    # Build fuzzed analyzer results.
    num_results = fdp.ConsumeIntInRange(1, 5)
    analyzer_results = []
    for _ in range(num_results):
        entity_type = ENTITY_TYPES[
            fdp.ConsumeIntInRange(0, len(ENTITY_TYPES) - 1)
        ]
        start = fdp.ConsumeIntInRange(0, max(0, len(text) - 2))
        end = fdp.ConsumeIntInRange(start + 1, min(start + 50, len(text)))
        score = fdp.ConsumeFloatInRange(0.0, 1.0)
        analyzer_results.append(
            RecognizerResult(
                entity_type=entity_type, start=start, end=end, score=score
            )
        )

    # Pick an anonymization operator.
    op_name = OPERATORS[fdp.ConsumeIntInRange(0, len(OPERATORS) - 1)]
    if op_name == "replace":
        new_value = fdp.ConsumeUnicodeNoSurrogates(
            fdp.ConsumeIntInRange(0, 32)
        )
        operator_config = OperatorConfig("replace", {"new_value": new_value})
    elif op_name == "mask":
        operator_config = OperatorConfig(
            "mask",
            {
                "chars_to_mask": fdp.ConsumeIntInRange(1, 20),
                "masking_char": "*",
                "from_end": fdp.ConsumeBool(),
            },
        )
    elif op_name == "hash":
        operator_config = OperatorConfig(
            "hash", {"hash_type": "sha256"}
        )
    else:
        operator_config = OperatorConfig("redact")

    try:
        result = engine.anonymize(
            text=text,
            analyzer_results=analyzer_results,
            operators={"DEFAULT": operator_config},
        )
    except (ValueError, RecursionError, MemoryError):
        return


def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
