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

import atheris
import sys
import mock

with atheris.instrument_imports():
    from google.cloud.logging_v2.handlers import _monitored_resources


global_fdp = None
def mock_retrieve_metadata_server(endpoint):
    """Mock for retrieve_metadata_server"""
    if global_fdp is None:
        return None
    if global_fdp.ConsumeIntInRange(1, 10) < 3:
        return None
    return global_fdp.ConsumeUnicodeNoSurrogates(30)

def TestInput(data):
    global global_fdp
    global_fdp = atheris.FuzzedDataProvider(data)

    # Mock the metadata server to avoid connections. The
    # retrieve_metadata_server will return fuzzer-seeded data.
    patch = mock.patch(
        "google.cloud.logging_v2.handlers._monitored_resources.retrieve_metadata_server",
        wraps=mock_retrieve_metadata_server,
    )
    # TODO: randomise relevant environment variables.
    with patch:
        _monitored_resources.detect_resource()


def main():
    atheris.Setup(sys.argv, TestInput, enable_python_coverage=True)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
