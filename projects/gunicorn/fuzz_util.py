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
    from gunicorn import util
    from gunicorn.errors import AppImportError

def TestInput(data):

    fdp = atheris.FuzzedDataProvider(data)

    util.is_ipv6(fdp.ConsumeString(100))
    util.warn(fdp.ConsumeString(100))
    util.split_request_uri(fdp.ConsumeString(100))

    try:
        util.parse_address(fdp.ConsumeString(100))
    except RuntimeError as e:
        if "is not a valid port number." not in str(e):
            raise e

    try:
        util.http_date(fdp.ConsumeInt(50))
    except OSError as e:
        if "Value too large for defined data type" not in str(e):
            raise e
    except (OverflowError,ValueError) as e:
        if "out of range" not in str(e):
            raise e

    try:
        util.to_bytestring(fdp.ConsumeString(100))
        util.to_bytestring(fdp.ConsumeString(100),'ascii')
    except UnicodeEncodeError as e:
        if "codec can't encode character" not in str(e):
            raise e

    try:
        util.import_app(fdp.ConsumeString(100))
    except (ValueError,ImportError,AppImportError) as e:
        error_list = [
             "Empty module name",
             "No module",
             "Failed to parse",
             "Function reference",
             "literal values",
             "attribute name",
             "find attribute",
             "takes",
             "inner",
             "find application object",
             "callable"
        ]
        expected_error = False
        for error in error_list:
            if error in str(e):
                expected_error = True
        if not expected_error:
            raise e

def main():
    atheris.Setup(sys.argv, TestInput, enable_python_coverage=True)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
