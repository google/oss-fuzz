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
from http.server import BaseHTTPRequestHandler, HTTPServer
import os
import random
import sys
import threading
import time
import urllib3

timeout = urllib3.util.Timeout(connect=1.0, read=1.0)
urllib_pool = urllib3.PoolManager(timeout=timeout)

PORT = 8011

GLOBAL_RESPONSE_MESSAGE = ""
GLOBAL_RESPONSE_CODE = 0
GLOBAL_CONTENT_ENCODING = None


class handler(BaseHTTPRequestHandler):
    def send_fuzzed_response(self):
        self.send_response(GLOBAL_RESPONSE_CODE)
        self.send_header("content-type", "text/html")
        if GLOBAL_CONTENT_ENCODING:
            self.send_header("content-encoding", GLOBAL_CONTENT_ENCODING)
        self.end_headers()

        self.wfile.write(bytes(GLOBAL_RESPONSE_MESSAGE, "utf-8"))

    def do_GET(self):
        self.send_fuzzed_response()

    def do_POST(self):
        self.send_fuzzed_response()

    def do_PUT(self):
        self.send_fuzzed_response()

    def do_PATCH(self):
        self.send_fuzzed_response()

    def do_OPTIONS(self):
        self.send_fuzzed_response()

    def do_DELETE(self):
        self.send_fuzzed_response()

    def do_HEAD(self):
        self.send_fuzzed_response()

    # Supress HTTP log output
    def log_request(self, code="-", size="-"):
        return


def run_webserver():
    with HTTPServer(("", PORT), handler) as server:
        server.serve_forever()


REQUEST_METHODS = ["POST", "GET", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH"]
CONTENT_ENCODING_TYPES = [None, "gzip", "deflate"]


def TestOneInput(input_bytes):
    global GLOBAL_RESPONSE_MESSAGE, GLOBAL_RESPONSE_CODE, GLOBAL_CONTENT_ENCODING
    fdp = atheris.FuzzedDataProvider(input_bytes)

    # Fuzz Http Response
    GLOBAL_RESPONSE_MESSAGE = fdp.ConsumeUnicodeNoSurrogates(sys.maxsize)
    GLOBAL_RESPONSE_CODE = fdp.ConsumeIntInRange(200, 599)
    GLOBAL_CONTENT_ENCODING = fdp.PickValueInList(CONTENT_ENCODING_TYPES)

    # Fuzz Http Request
    requestType = fdp.PickValueInList(REQUEST_METHODS)
    # Optionally provide request headers
    requestHeaders = urllib3._collections.HTTPHeaderDict({})
    for i in range(0, fdp.ConsumeIntInRange(0, 10)):
        requestHeaders.add(
            fdp.ConsumeString(sys.maxsize), fdp.ConsumeString(sys.maxsize)
        )
    requestHeaders = None if fdp.ConsumeBool() else requestHeaders

    # Optionally generate form data for request
    formData = {}
    for i in range(0, fdp.ConsumeIntInRange(0, 100)):
        formData[fdp.ConsumeString(sys.maxsize)] = fdp.ConsumeString(sys.maxsize)
    formData = None if fdp.ConsumeBool() else formData

    # Optionally generate request body
    requestBody = None if fdp.ConsumeBool() else fdp.ConsumeString(sys.maxsize)

    r = urllib_pool.request(
        requestType,
        f"http://localhost:{PORT}/",
        headers=requestHeaders,
        fields=formData,
        body=requestBody
    )
    r.status
    r.data
    r.headers

def main():
    # Try and get an open port to run our test web server
    for attempt in range(10):
        try:
            PORT = random.randint(8000,9999)
            x = threading.Thread(target=run_webserver, daemon=True)
            x.start()
            break
        except OSError as e:
            pass 

    time.sleep(0.5)  # Short delay to start test server

    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
