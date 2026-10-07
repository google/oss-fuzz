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
import mock
import atheris
import tempfile

import json
import mock
from google_auth_oauthlib import helpers


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    config_file = tempfile.NamedTemporaryFile(mode="wt")
    try:
        payload = json.loads(fdp.ConsumeUnicodeNoSurrogates(1024))
    except:
        return
    if type(payload) is not dict:
        return
    config_file.write(json.dumps(payload))

    try:
        helpers.session_from_client_secrets_file(
            config_file.name, scopes=mock.sentinel.scopes
        )
    except ValueError as ve:
        legit_exceptions = [
            "Client secrets must be for a web or installed app.",
            "Client secrets is not in the correct format."
        ]
        legit = False
        for msg in legit_exceptions:
            if msg in str(ve):
                legit = True
        if not legit:
            raise ve


def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
