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
     from retry import *

IS_ERROR = True
ERROR_MSG = "TestingError"

class TestingError(Exception):
    def __init__(self, message):
        super().__init__(message)

def error_method():
    global IS_ERROR
    IS_ERROR = not IS_ERROR

    global ERROR_MSG

    if IS_ERROR:
        raise TestingError(ERROR_MSG)
    else:
       return

def TestInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    global IS_ERROR
    IS_ERROR = fdp.ConsumeBool()

    global ERROR_MSG
    ERROR_MSG = fdp.ConsumeString(20)

    try:
        retry_call(error_method,logger=None)
        retry_call(
            error_method,
            exceptions=TestingError,
            tries=fdp.ConsumeIntInRange(-1,100),
            delay=fdp.ConsumeIntInRange(1,10),
            logger=None
        )
    except (TestingError, ValueError):
        # Expected when retry limit is reached
        pass

    @retry(logger=None)
    def wrapper_one():
        error_method()

    @retry(
        ValueError,
        tries=fdp.ConsumeIntInRange(-1,100),
        delay=fdp.ConsumeIntInRange(1,10),
        logger=None
    )
    def wrapper_two():
        error_method()

    try:
        wrapper_one()
        wrapper_two()
    except (TestingError, ValueError):
        # Expected when retry limit it reached
        pass

def main():
    atheris.Setup(sys.argv, TestInput, enable_python_coverage=True)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
