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

import io
import digest

def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    alg = fdp.ConsumeUnicodeNoSurrogates(15)
    b1 = fdp.ConsumeBytes(sys.maxsize)
    try:
        s1 = digest.digest(io.BytesIO(b1), alg, len(b1))
    except SystemExit:
        pass
    except TypeError as e:
        if "name must be a string" in str(e):
            # non-interesting bug. Let the fuzzer continue
            pass
        else:
            raise e

def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
