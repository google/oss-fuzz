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
    from smart_open.utils import *

def TestInput(data):
    if len(data) < 10:
       return

    fdp = atheris.FuzzedDataProvider(data)

    #Fuzz clamp
    clamp(
        fdp.ConsumeInt(10),
        fdp.ConsumeInt(10),
        None if fdp.ConsumeBool() else fdp.ConsumeInt(10)
    )

    #Fuzz check_kwargs
    kwargs = {}
    for i in range(1,fdp.ConsumeIntInRange(1,10)):
        kwargs[fdp.ConsumeString(5)]=fdp.ConsumeString(10)
    try:
        check_kwargs(fdp.ConsumeString(10),kwargs)
    except TypeError as e:
        if "is not a callable object" not in str(e):
            raise e

    #Fuzz make_range_string
    try:
        make_range_string(
            None if fdp.ConsumeBool() else fdp.ConsumeInt(10),
            None if fdp.ConsumeBool() else fdp.ConsumeInt(10)
        )
    except ValueError as e:
        if "make_range_string requires either a stop or start value" not in str(e):
            raise e
	
    #Fuzz content_range
    content_range = "%s %d-%d/%d"%(
        fdp.ConsumeString(10),
        fdp.ConsumeInt(10),
        fdp.ConsumeInt(10),
        fdp.ConsumeInt(10)
    )
    try:
       parse_content_range(content_range)
    except ValueError as e:
        error_list = [
            "invalid literal for int() with base 10",
            "not enough values to unpack"
        ]
        expected_error = False
        for error in error_list:
            if error in str(e):
                expected_error = True
        if not expected_error:
            raise e

    #Fuzz safe_urlsplit
    try:
        safe_urlsplit(fdp.ConsumeString(100))
    except ValueError as e:
        if "Invalid IPv6 URL" not in str(e):
             raise e
def main():
    atheris.Setup(sys.argv, TestInput, enable_python_coverage=True)
    atheris.instrument_all()
    atheris.Fuzz()

if __name__ == "__main__":
  main()
