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
"""Targets: https://github.com/advisories/GHSA-435p-f82x-mxwm"""

import os
import sys
import atheris
import sanlib

import yamale


def TestOneInput(data):
    assist = True
    fdp = atheris.FuzzedDataProvider(data)

    str_to_parse = fdp.ConsumeUnicodeNoSurrogates(1024)
    try:
        yamale.syntax.parse(str_to_parse)
    except (
        SyntaxError,
        ValueError,
        MemoryError,
        ZeroDivisionError,
        ValueError
    ) as e:
        pass


def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
