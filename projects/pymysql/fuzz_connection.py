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

import sys
import atheris
import threading
import socket
import time

import configparser
import pymysql
from pymysql import connections, constants


fuzzed_input = b""

# somehow ugly as fuzzing cannot be run in parallel
def SetFuzzedInput(input_bytes):
 global fuzzed_input
 fuzzed_input = input_bytes

class ServerThread(threading.Thread):
  def __init__(self):
    self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    self.s.bind(("127.0.0.1", 8001))
    self.s.listen(1)

    threading.Thread.__init__(self)

  def run(self):
    global fuzzed_input
    conn, addr = self.s.accept()
    conn.settimeout(0.3)
    try:
      conn.recv(1024)
    except:
      pass
    conn.send(fuzzed_input)
    time.sleep(0.005)
    conn.close()
    self.s.shutdown(1)
    self.s.close()
    time.sleep(0.01)


def TestOneInput(data):
  fdp = atheris.FuzzedDataProvider(data)
  local_config_file = "/tmp/my.cnf"
  with open(local_config_file, "w") as cfg:
    cfg.write(fdp.ConsumeUnicodeNoSurrogates(1024))

  # Catch config parser errors
  try:
    c = connections.Connection(
      db=None,
      read_default_file=local_config_file,
      ssl_disabled=True,
      defer_connect=True
    )
  except configparser.Error:
    return
  c.port = 8001
  c.host = "127.0.0.1"

  SetFuzzedInput(fdp.ConsumeBytes(512))
  t1 = ServerThread()
  t1.start()

  try:
    c.connect(sock=None)
  except pymysql.err.MySQLError:
    pass
  t1.join()


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
