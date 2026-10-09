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
import socket
import sys
import threading
import time

import urllib3

# Setup http mocking
GLOBAL_RESPONSE_BODY = b""
GLOBAL_RESPONSE_CODE = 0
GLOBAL_CONTENT_TYPE = b""


class ServerThread(threading.Thread):
    def __init__(self) -> None:
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.s.bind(("127.0.0.1", 8001))
        self.s.listen(1)
        super().__init__()

    def run(self) -> None:
        global GLOBAL_RESPONSE_CODE, GLOBAL_CONTENT_TYPE, GLOBAL_RESPONSE_BODY
        conn, addr = self.s.accept()
        conn.recv(1024)
        conn.send(
            b"HTTP/1.1 %d FOO\r\nContent-Type: %b\r\n\r\n%b"
            % (GLOBAL_RESPONSE_CODE, GLOBAL_CONTENT_TYPE, GLOBAL_RESPONSE_BODY)
        )
        time.sleep(0.005)
        conn.close()
        self.s.shutdown(1)
        self.s.close()
        time.sleep(0.01)


REQUEST_METHODS = ["POST", "GET", "HEAD", "PUT"]

def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    global GLOBAL_RESPONSE_BODY, GLOBAL_RESPONSE_CODE, GLOBAL_CONTENT_TYPE
    GLOBAL_RESPONSE_BODY = fdp.ConsumeBytes(sys.maxsize)
    GLOBAL_RESPONSE_CODE = fdp.ConsumeIntInRange(200, 599)
    GLOBAL_CONTENT_TYPE = fdp.ConsumeBytes(sys.maxsize)

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

    timeout = urllib3.util.Timeout(connect=0.1, read=0.1)
    urllib_pool = urllib3.poolmanager.PoolManager(timeout=timeout)

    t1 = ServerThread()
    t1.start()

    response = urllib_pool.request(
        requestType,
        "http://localhost:8001/", 
        headers=requestHeaders,
        fields=formData
    )
    
    response.status
    response.data
    response.headers

    t1.join()


def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
