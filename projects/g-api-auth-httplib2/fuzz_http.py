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

import six
from six.moves import http_client
import mock
import httplib2
import google_auth_httplib2


# Mocks for fuzzing. Inspired by testing infra. Main difference is we have
# added logic to handle the event where the MockHTTP has run out of
# responses an appropriate exception is thrown that we catch in the fuzzer.
class FuzzMockHttp(object):
    def __init__(self, responses, headers=None):
        self.responses = responses
        self.requests = []
        self.headers = headers or {}
        self.add_certificate = mock.Mock(return_value=None)

    def request(
        self,
        url,
        method="GET",
        body=None,
        headers=None,
        redirections=httplib2.DEFAULT_MAX_REDIRECTS,
        connection_type=None,
    ):
        self.requests.append(
            (method, url, body, headers, redirections, connection_type)
        )
        if len(self.responses) == 0:
            raise Exception("FUZZ: No more responses")
        return self.responses.pop(0)


class FuzzMockResponse(object):
    def __init__(self, status=http_client.OK, data=b""):
        self.status = status
        self.data = data

    def __iter__(self):
        yield self
        yield self.data


class FuzzMockCredentials(object):
    def __init__(self, token="token"):
        self.token = token

    def apply(self, headers):
        headers["authorization"] = self.token

    def before_request(self, request, method, url, headers):
        self.apply(headers)

    def refresh(self, request):
        self.token += "1"


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    mock_credentials = mock.Mock(wraps=FuzzMockCredentials(fdp.ConsumeUnicodeNoSurrogates(10)))
    if fdp.ConsumeBool() == True:
        mock_credentials.apply({'authorization': ""})

    # Create responses. We need at least two.
    http_codes = [400, 401, 403, 404, 405, 413, 415, 429, 500, 503, 504]
    mock_responses = []
    for i in range(fdp.ConsumeIntInRange(1, 10)):
        mock_responses.append(
            FuzzMockResponse(
                status = http_codes[fdp.ConsumeIntInRange(0, len(http_codes)-1)],
                data = fdp.ConsumeBytes(100)
            )
        )
    mock_http = FuzzMockHttp(mock_responses)

    authed_http = google_auth_httplib2.AuthorizedHttp(
        mock_credentials, http=mock_http
    )
    try:
        r, d = authed_http.request(
            "http://localhost:8001",
            fdp.ConsumeUnicodeNoSurrogates(10),
            None,
            None,
            httplib2.DEFAULT_MAX_REDIRECTS,
            None
        )
    except Exception as e:
        if "FUZZ" in str(e):
            pass
        else:
            raise e


def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
