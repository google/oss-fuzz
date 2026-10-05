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
from jwt.algorithms import RSAAlgorithm
from jwt.api_jws import PyJWS
from jwt import PyJWKClient
import json
from collections.abc import Mapping
import copy
from urllib.error import URLError


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


def test_JWS_encoding(data):
    """Checks PyJWS encoding does not fail"""
    fdp = atheris.FuzzedDataProvider(data)
    payload = fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 100))
    key = "fuzzing"
    PyJWS().encode(payload=payload, key=key, headers={
        fdp.ConsumeUnicodeNoSurrogates(1024): fdp.ConsumeUnicodeNoSurrogates(1024)})


def test_decode_complete(data):
    """Checks jwt decode_complete does not fail"""
    fdp = atheris.FuzzedDataProvider(data)
    s1 = fdp.ConsumeUnicodeNoSurrogates(1024)
    key = "fuzzing"
    try:
        _ = jwt.api_jwt.decode_complete(
            jwt=s1, options={"verify_signature": False}, algorithms=[["HS512", "HS256"]])
        _ = CompressedPyJWT().decode_complete(
            s1, key=key, algorithms=["HS256"])
    except jwt.exceptions.PyJWTError:
        pass


def test_roundtrip_with_RS256(data):
    """Check payload == decoded(encoded(payload)) using RS256"""
    fdp = atheris.FuzzedDataProvider(data)
    try:
        payload = json.loads(fdp.ConsumeUnicodeNoSurrogates(1024))
        keyfile = json.loads(fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 100)))
    except:
        return
    # Only continue if correct type was created as payload and keyfile.
    if not isinstance(payload, Mapping) and not isinstance(keyfile, Mapping):
        return
    try:
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)
        key = algo.from_jwk(keyfile)
        decoded = jwt.decode(payload, key, algorithms=["RS256"])
    except jwt.exceptions.PyJWTError:
        return
    assert decoded == payload


def test_registered_claim_names(data):
    """Checks the use of registered claim names does not cause encoding to fail"""
    fdp = atheris.FuzzedDataProvider(data)
    try:
        payload = json.loads(fdp.ConsumeUnicodeNoSurrogates(1024))
    except:
        return
    # Only continue if correct type was created as payload.
    if not isinstance(payload, Mapping):
        return

    payload_exp = copy.deepcopy(payload)
    payload_nbf = copy.deepcopy(payload)
    payload_iss = copy.deepcopy(payload)
    payload_aud = copy.deepcopy(payload)
    payload_iat = copy.deepcopy(payload)
    key = "fuzzing"

    payload_exp["exp"] = fdp.ConsumeIntInRange(0, 10)
    jwt.encode(payload_exp, key)

    payload_nbf["nbf"] = fdp.ConsumeIntInRange(0, 10)
    jwt.encode(payload_nbf, key)

    payload_iss["iss"] = fdp.ConsumeUnicodeNoSurrogates(
        fdp.ConsumeIntInRange(0, 100))
    jwt.encode(payload_iss, key)

    payload_aud["aud"] = fdp.ConsumeUnicodeNoSurrogates(
        fdp.ConsumeIntInRange(0, 100))
    jwt.encode(payload_aud, key)

    payload_iat["iat"] = fdp.ConsumeIntInRange(0, 10)
    jwt.encode(payload_iat, key)


def TestOneInput(data):
    test_decoding(data)
    test_roundtrip(data)
    test_roundtrip_with_RS256(data)
    test_decode_complete(data)
    test_JWS_encoding(data)
    test_registered_claim_names(data)


def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
