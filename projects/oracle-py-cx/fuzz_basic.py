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
import time
import socket
import threading
import cx_Oracle

fuzzed_input = b""


def SetFuzzedInput(input_bytes):
    global fuzzed_input
    fuzzed_input = input_bytes


class ServerThread(threading.Thread):
    def __init__(self, port):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.s.bind(("127.0.0.1", port))
        self.s.settimeout(0.4)
        self.s.listen(1)

        threading.Thread.__init__(self)

    def run(self):
        global fuzzed_input
        try:
            conn, addr = self.s.accept()
        except socket.timeout:
            return
        conn.recv(1024)
        conn.send(fuzzed_input)
        time.sleep(0.005)
        conn.close()
        self.s.shutdown(1)
        self.s.close()
        time.sleep(0.01)


@atheris.instrument_func
def TestInput(data):
    port = None
    for i in range(8009, 8100):
        try:
            t1 = ServerThread(i)
        except OSError:
            # If the address is already in use by another
            continue
        port = i
        break

    if port == None:
        return

    t1.start()

    fdp = atheris.FuzzedDataProvider(data)
    args = dict()
    args['user'] = fdp.ConsumeUnicodeNoSurrogates(64)
    args['password'] = fdp.ConsumeUnicodeNoSurrogates(64)
    args['dsn'] = f"127.0.0.1:{port}"
    if fdp.ConsumeBool():
        args['newpassword'] = fdp.ConsumeUnicodeNoSurrogates(64)
    if fdp.ConsumeBool():
        args['nencoding'] = fdp.ConsumeUnicodeNoSurrogates(64)

    SetFuzzedInput(fdp.ConsumeBytes(400))
    try:
        connection = cx_Oracle.connect(**args)
    except cx_Oracle.DatabaseError:
        connection = None
        pass

    if connection is None:
        t1.join()
        return

    cursor = connection.cursor()
    cursor.execute(fdp.ConsumeUnicodeNoSurrogates(1024))
    t1.join()


def main(): 
    atheris.Setup(sys.argv, TestInput, enable_python_coverage=True)
    atheris.instrument_all()
    atheris.Fuzz()


if __name__ == "__main__":
    main()
