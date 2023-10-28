#!/usr/bin/python3

# Copyright 2023 Google LLC
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
import httpretty
import sys

import urllib3

# Setup http mocking
GLOBAL_RESPONSE_BODY = ""
GLOBAL_RESPONSE_CODE = 0
GLOBAL_CONTENT_TYPE = ""

def request_callback(request, uri, headers):
    headers['Content-Type'] = GLOBAL_CONTENT_TYPE
    return [GLOBAL_RESPONSE_CODE, headers, GLOBAL_RESPONSE_BODY]

httpretty.enable(verbose=True, allow_net_connect=False)
httpretty.register_uri(httpretty.GET, "http://www.test.com", body=request_callback)
httpretty.register_uri(httpretty.POST, "http://www.test.com", body=request_callback)
httpretty.register_uri(httpretty.HEAD, "http://www.test.com", body=request_callback)
httpretty.register_uri(httpretty.PUT, "http://www.test.com", body=request_callback)

REQUEST_METHODS = ["POST", "GET", "HEAD", "PUT"]

def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    global GLOBAL_RESPONSE_BODY, GLOBAL_RESPONSE_CODE, GLOBAL_CONTENT_TYPE
    GLOBAL_RESPONSE_BODY = fdp.ConsumeUnicodeNoSurrogates(sys.maxsize)
    GLOBAL_RESPONSE_CODE = fdp.ConsumeIntInRange(200, 599)
    GLOBAL_CONTENT_TYPE = fdp.ConsumeString(sys.maxsize)

    requestType = fdp.PickValueInList(REQUEST_METHODS)

    # Optionally provide request headers
    requestHeaders = urllib3._collections.HTTPHeaderDict({})
    for i in range(0, fdp.ConsumeIntInRange(0, 10)):
        requestHeaders.add(
            fdp.ConsumeString(sys.maxsize), fdp.ConsumeString(sys.maxsize)
        )
    requestHeaders = None if fdp.ConsumeBool() else requestHeaders

    # Optionally generate form data
    formData = {}
    for i in range(0, fdp.ConsumeIntInRange(0, 100)):
        formData[fdp.ConsumeString(sys.maxsize)] = fdp.ConsumeString(sys.maxsize)
    formData = None if fdp.ConsumeBool() else formData

    response = urllib3.request(
        requestType,
        "http://www.test.com",
        headers=requestHeaders,
        fields=formData
    )
    
    response.status
    response.data
    response.headers

def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
