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
"""Fuzzer for Packetizer"""

import os
import sys
import atheris

from hashlib import sha1

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher, modes

from paramiko import Message, Packetizer
from paramiko.common import byte_chr, zero_byte

# Extract path of fuzzer so we can include loop.py
if getattr(sys, 'frozen', False):
    app_path = os.path.dirname(sys.executable)
elif __file__:
    app_path = os.path.dirname(__file__)
else:
    raise Exception("Could not extract path needed to import loop.py")
sys.path.append(app_path)
from loop import LoopSocket

def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    rsock = LoopSocket()
    wsock = LoopSocket()
    rsock.link(wsock)
    p = Packetizer(wsock)
    encryptor = Cipher(
        algorithms.AES(zero_byte * 16),
        modes.CBC(byte_chr(fdp.ConsumeIntInRange(0, 255)) * 16),
        backend=default_backend(),
    ).encryptor()
    p.set_outbound_cipher(
        encryptor,
        16,
        sha1,
        12,
        byte_chr(fdp.ConsumeIntInRange(0, 255)) * 20
    )

    m = Message()
    # Messages need to be at least 16 bytes long, so we'll include
    # at least 16 items.
    for i in range(fdp.ConsumeIntInRange(16, 32)):
        op = fdp.ConsumeIntInRange(0,5)
        if op == 0:
            m.add(fdp.ConsumeUnicodeNoSurrogates(20))
        elif op == 1:
            m.add(fdp.ConsumeIntInRange(0, 4294967295))
        elif op == 2:
            m.add(fdp.ConsumeBool())
        elif op == 3:
            l1 = list()
            for i in range(1, 10):
                l1.append(fdp.ConsumeUnicodeNoSurrogates(20))
            m.add(l1)
        elif op == 4:
            m.add_bytes(fdp.ConsumeBytes(20))
        elif op == 5:
            m.add_byte(byte_chr(fdp.ConsumeIntInRange(0,255)))
    p.send_message(m)
    rsock.recv(sys.maxsize)


def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
