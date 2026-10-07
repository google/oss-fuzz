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
import socket
import time
from threading import Thread
with atheris.instrument_imports():
    import requests
    from requests.exceptions import InvalidURL,ConnectionError
    from requests_ntlm2 import HttpNtlmAuth

class ServerThread(Thread):
    def __init__(self, fdp):
        self.fdp = fdp

        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.s.bind(("127.0.0.1", 8001))
        self.s.listen(1)

        Thread.__init__(self)

    def run(self):
        conn, addr = self.s.accept()
        conn.recv(self.fdp.ConsumeIntInRange(1024,2048))
        conn.send(self.fdp.ConsumeBytes(2048))
        time.sleep(0.005)
        conn.close()
        self.s.shutdown(1)
        self.s.close()
        time.sleep(0.01)

def TestInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    t1 = ServerThread(fdp)
    t1.start()

    session = requests.Session()
    auth = HttpNtlmAuth(fdp.ConsumeString(50),fdp.ConsumeString(10))
    session.auth = HttpNtlmAuth(fdp.ConsumeString(50),fdp.ConsumeString(10))

    try:
       requests.get('http://localhost:8001/%s'%fdp.ConsumeString(20),auth=auth)
       session.get('http://localhost:8001/%s'%fdp.ConsumeString(20))
    except (InvalidURL,ConnectionError) as e:
       pass

    t1.join()

def main(): 
    atheris.Setup(sys.argv, TestInput, enable_python_coverage=True)
    atheris.instrument_all()
    atheris.Fuzz()

if __name__ == "__main__":
  main()
