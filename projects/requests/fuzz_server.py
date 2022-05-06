#!/usr/bin/python3

# Copyright 2021 Google LLC
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
import time
import threading

with atheris.instrument_imports():
    import requests

fuzzed_input = b""

# somehow ugly as fuzzing cannot be run in parallel
def SetFuzzedInput(input_bytes):
    global fuzzed_input
    fuzzed_input = input_bytes

class ServerThread(threading.Thread):

    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        global fuzzed_input
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("127.0.0.1", 8001))
        s.listen(1)
        while 1:
            conn, addr = s.accept()
            conn.recv(1024)
            conn.send(fuzzed_input)
            time.sleep(0.005)
            conn.close()

def TestOneInput(input_bytes):
  SetFuzzedInput(input_bytes)
  try:
    r = requests.get('http://127.0.0.1:8001/', timeout=0.01)
    r.status_code
    r.headers
    r.text
  except requests.exceptions.RequestException as e:
    pass


def main():
  atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
  t1 = ServerThread()
  # Launch threads
  t1.start()

  atheris.Fuzz()
  # Wait for threads to finish
  t1.join()


if __name__ == "__main__":
  main()
