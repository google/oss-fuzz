#!/usr/bin/python3
# Copyright 2022 Google LLC
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

import os
import sys
import atheris

import jwt
import json
from collections.abc import Mapping


def test_decoding(data):
    """Checks jwt decoding does not fail"""
    fdp = atheris.FuzzedDataProvider(data)
    s1 = fdp.ConsumeUnicodeNoSurrogates(1024)
    try:
        _ = jwt.decode(s1, algorithms=["HS256"])
    except jwt.exceptions.PyJWTError:
        pass


def test_roundtrip(data):
    """Check payload == decoded(encoded(payload))"""
    fdp = atheris.FuzzedDataProvider(data)
    try:
        payload = json.loads(fdp.ConsumeUnicodeNoSurrogates(1024))
    except:
        return
    # Only continue if correct type was created as payload.
    if not isinstance(payload, Mapping): 
        return

    key = "fuzzing"
    try:
        jwt_message = jwt.encode(payload, key, algorithm="HS256")
        decoded_payload = jwt.decode(jwt_message, key, algorithms=["HS256"])
    except jwt.exceptions.PyJWTError:
        return
    assert decoded_payload == payload 


def TestOneInput(data):
    test_decoding(data)
    test_roundtrip(data)


def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
