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
import random
with atheris.instrument_imports():
     from decorator import *

def base_func(*args, **kw):
    pass

def TestInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    try:
        FunctionMaker.create(
            "f%s(%s)"%(fdp.ConsumeString(20),fdp.ConsumeString(20)),
            "base_func()",
            dict(f=base_func),
            addsource=fdp.ConsumeBool()
        )
    except Exception as e:
        if "Error in generated code" not in str(e):
             raise e

def main():
    atheris.Setup(sys.argv, TestInput, enable_python_coverage=True)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
