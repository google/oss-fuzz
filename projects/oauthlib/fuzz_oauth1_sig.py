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

from oauthlib.oauth1.rfc5849.signature import (
    verify_hmac_sha1, verify_rsa_sha512
)


class FuzzMockRequest:
    def __init__(
        self,
        method,
        uri_str,
        params,
        signature
    ):
        self.uri = uri_str
        self.http_method = method
        self.params = params
        self.signature = signature


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    mr = FuzzMockRequest(
        method = fdp.ConsumeUnicodeNoSurrogates(64),
        uri_str = fdp.ConsumeUnicodeNoSurrogates(64),
        params = [
                    (
                        fdp.ConsumeUnicodeNoSurrogates(64),
                        fdp.ConsumeUnicodeNoSurrogates(64)
                    )
                ],
        signature = fdp.ConsumeUnicodeNoSurrogates(64),
    )
    try:
        verify_hmac_sha1(mr, None, None)
    except ValueError:
        pass

    try:
        verify_rsa_sha512(
            mr, fdp.ConsumeUnicodeNoSurrogates(512)
        )
    except ValueError:
        pass


def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
