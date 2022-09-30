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
        'Invalid base64-encoded string',
        'could not be converted to',
        'contains invalid characters under NFKC normalization'
    ]

    try:
        helpers.scopes_to_string([
            fdp.ConsumeUnicodeNoSurrogates(20),
            fdp.ConsumeUnicodeNoSurrogates(20)
        ])
        helpers.scopes_to_string(fdp.ConsumeUnicodeNoSurrogates(20))

        helpers.string_to_scopes(fdp.ConsumeUnicodeNoSurrogates(100))

        helpers.parse_unique_urlencoded(fdp.ConsumeUnicodeNoSurrogates(100))

        helpers.update_query_params(
            fdp.ConsumeUnicodeNoSurrogates(100),{
                fdp.ConsumeUnicodeNoSurrogates(10):fdp.ConsumeUnicodeNoSurrogates(20),
                fdp.ConsumeUnicodeNoSurrogates(10):fdp.ConsumeUnicodeNoSurrogates(20),
                fdp.ConsumeUnicodeNoSurrogates(10):fdp.ConsumeUnicodeNoSurrogates(20)
        })

        helpers._add_query_parameter(
            fdp.ConsumeUnicodeNoSurrogates(100),
            fdp.ConsumeUnicodeNoSurrogates(10),
            fdp.ConsumeUnicodeNoSurrogates(20)
        )

        helpers.validate_file(fdp.ConsumeUnicodeNoSurrogates(100))

        helpers._json_encode(fdp.ConsumeUnicodeNoSurrogates(100))

        input = fdp.ConsumeUnicodeNoSurrogates(100).encode('ascii', errors='ignore').decode()
        helpers._to_bytes(input)
        helpers._from_bytes(fdp.ConsumeUnicodeNoSurrogates(100))

        helpers._urlsafe_b64encode(fdp.ConsumeUnicodeNoSurrogates(100))
        input = fdp.ConsumeUnicodeNoSurrogates(100).encode('ascii', errors='ignore').decode()
        helpers._urlsafe_b64decode(input)
    except (ValueError, IOError, binascii.Error) as e:
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
