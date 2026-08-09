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

def TestInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    @decorator
    def dummy_decorator(func, dummy=1, *args, **kw):
        result = func(*args, **kw)

    @decoratorx
    def dummy_decoratorx(func, *args, **kw):
        result = func(*args, **kw)

    def dummy_decorate(func, dummy=1, *args, **kw):
        result = func(*args, **kw)

    @dummy_decorator(dummy=fdp.ConsumeInt(8))
    def func1(dummy):
        pass

    @dummy_decoratorx
    def func2(dummy):
        pass

    def func3(dummy):
        pass

    choice = fdp.ConsumeIntInRange(1,3)
	
    if choice == 1:
        func1(fdp.ConsumeBytes(fdp.ConsumeIntInRange(1,1000)))
    if choice == 2:
        func2(fdp.ConsumeBytes(fdp.ConsumeIntInRange(1,1000)))
    if choice == 3:
        decorate(func3,dummy_decorate,fdp.ConsumeInt(fdp.ConsumeIntInRange(1,1000)))
        func3(fdp.ConsumeBytes(10))

def main():
    atheris.Setup(sys.argv, TestInput, enable_python_coverage=True)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
