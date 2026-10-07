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
with atheris.instrument_imports():
    from redis.utils import *

def TestInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    safe_str(fdp.ConsumeString(50))
    safe_str(fdp.ConsumeUnicode(50))
    safe_str(fdp.ConsumeBytes(50))
    safe_str(fdp.ConsumeInt(8))
    safe_str(fdp.ConsumeFloat())
    safe_str(fdp.ConsumeBool())

    dict1={
        fdp.ConsumeString(10):fdp.ConsumeUnicode(10),
        fdp.ConsumeString(10):fdp.ConsumeBytes(10),
        fdp.ConsumeString(10):fdp.ConsumeString(10),
    }

    merge_result(fdp.ConsumeString(50),dict1)
    merge_result(fdp.ConsumeString(50),dict())

def main():
    atheris.Setup(sys.argv, TestInput, enable_python_coverage=True)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
