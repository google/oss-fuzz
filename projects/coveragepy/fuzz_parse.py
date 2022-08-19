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

import sys
import atheris

from coverage.exceptions import NotPython
from coverage.parser import PythonParser


def TestOneInput(data):
    """Fuzzer for PythonParser"""
    fdp = atheris.FuzzedDataProvider(data)
    
    t = fdp.ConsumeUnicodeNoSurrogates(1024)
    if not t:
        return
    
    try:
        p = PythonParser(text = t)
        p.parse_source()
    except (NotPython, MemoryError) as e2:
        # Catch Memory error for stack overflows
        # Catch NotPython issues raised by coveragepy
        pass
    except ValueError as e:
        if "source code string cannot contain null bytes" in str(e):
            # Not interesting
            pass
        else:
            raise e


def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
