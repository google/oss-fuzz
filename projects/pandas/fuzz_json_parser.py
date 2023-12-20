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
"""This fuzzer script specifically targets the pandas json parser."""

import sys
import atheris
import pandas as pd
import io

from pandas.errors import (
    EmptyDataError,
    ParserError,
)


def TestReadJson(data):
    fdp = atheris.FuzzedDataProvider(data)

    try:
        fuzzed_json = fdp.ConsumeUnicode(sys.maxsize)
        pd.read_json(io.StringIO(fuzzed_json), orient='index')
    except (
            ParserError,  # If the data is not valid JSON
            EmptyDataError,  # If the data is emtpy or contains only whitespaces
            ValueError  # If the data is not line-delimited JSON format
    ):
        pass


def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestReadJson)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
