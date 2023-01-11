#!/usr/bin/python3
# Copyright 2023 Google LLC
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
import sys
import atheris

from google.cloud.bigquery_storage_v1.types import ReadSession
from google.protobuf.json_format import Parse


def TestOneInput(data):
    """Fuzzer that creates a random read session and parses
    the attached avro session. The main point is to ensure
    none of the parsing routines have insecure calls and
    that the parsing routines can work with arbitrary ReadSessions.
    """
    fdp = atheris.FuzzedDataProvider(data)
    try:
        # Create a random session
        msg = Parse(fdp.ConsumeUnicodeNoSurrogates(sys.maxsize), ReadSession())
    except Exception:
        return

    avro_parser = _AvroStreamParser(msg)
    avro_parser.to_dataframe()


def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
