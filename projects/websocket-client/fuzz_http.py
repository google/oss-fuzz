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

from websocket._exceptions import WebSocketException
from websocket._http import read_headers, _tunnel


class FuzzMock:
    """FuzzMock class inspired by SockMock"""
    def __init__(self, packet):
        self.data = [packet]
        self.sent = []

    def gettimeout(self):
        return None

    def recv(self, bufsize):
        if self.data:
            e = self.data.pop(0)
            if isinstance(e, Exception):
                raise e
            if len(e) > bufsize:
                self.data.insert(0, e[bufsize:])
            return e[:bufsize]

    def send(self, data):
        self.sent.append(data)
        return len(data)


def TestOneInput(data):
    try:
        fdp = atheris.FuzzedDataProvider(data)
        # Create mock socket with fuzzer-derived data.
        mock_sock = FuzzMock(fdp.ConsumeBytes(512))
        _tunnel(
            mock_sock,
            fdp.ConsumeUnicodeNoSurrogates(200),
            fdp.ConsumeIntInRange(1, 1000),
            (
                fdp.ConsumeUnicodeNoSurrogates(100),
                fdp.ConsumeUnicodeNoSurrogates(100)
            )
        )
    except WebSocketException:
        pass
    except UnicodeDecodeError:
        pass
        
    
def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
