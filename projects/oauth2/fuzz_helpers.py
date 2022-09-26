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
import binascii
with atheris.instrument_imports():
    import oauth2client._helpers as helpers

def TestInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    expected_error_list = [
        'URL-encoded content contains a repeated value:',
	'Invalid IPv6 URL',
        'Is a symbolic link.',
        'Is a directory',
        'Incorrect padding',
        'codec can\'t decode byte',
        'codec can\'t encode character',
        'could not be converted to'
    ]

    try:
        helpers.scopes_to_string([
            fdp.ConsumeString(20),
            fdp.ConsumeString(20)
        ])
        helpers.scopes_to_string(fdp.ConsumeString(20))

        helpers.string_to_scopes(fdp.ConsumeString(100))

        helpers.parse_unique_urlencoded(fdp.ConsumeString(100))

        helpers.update_query_params(
            fdp.ConsumeString(100),{
                fdp.ConsumeString(10):fdp.ConsumeString(20),
                fdp.ConsumeString(10):fdp.ConsumeString(20),
                fdp.ConsumeString(10):fdp.ConsumeString(20)
        })

        helpers._add_query_parameter(
            fdp.ConsumeString(100),
            fdp.ConsumeString(10),
            fdp.ConsumeString(20)
        )

        helpers.validate_file(fdp.ConsumeString(100))

        helpers._json_encode(fdp.ConsumeString(100))

        helpers._to_bytes(fdp.ConsumeString(100))
        helpers._from_bytes(fdp.ConsumeBytes(100))

        helpers._urlsafe_b64encode(fdp.ConsumeString(100))
        helpers._urlsafe_b64decode(fdp.ConsumeString(100))
    except (ValueError, UnicodeDecodeError, IOError, binascii.Error) as e:
        expected = False
        for expected_error in expected_error_list:
            if expected_error in str(e):
                    expected = True
                    break
        if not expected:
            raise e

def main():
    atheris.Setup(sys.argv, TestInput, enable_python_coverage=True)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
