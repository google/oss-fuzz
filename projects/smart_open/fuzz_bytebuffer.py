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
import os
with atheris.instrument_imports():
    from smart_open.bytebuffer import ByteBuffer

def TestInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    chunk_size = fdp.ConsumeIntInRange(1,100)
    message_byte = []
    for i in range(1,fdp.ConsumeIntInRange(1,10)):
        message_byte.append(fdp.ConsumeBytes(chunk_size))

    buffer = ByteBuffer(chunk_size = fdp.ConsumeIntInRange(1,100))

    buffer.empty()
    buffer.fill(iter(message_byte))
    buffer.peek()
    buffer.read(fdp.ConsumeIntInRange(1,chunk_size))
    buffer.readline(fdp.ConsumeBytes(1))
    buffer.empty()

def main():
    atheris.Setup(sys.argv, TestInput, enable_python_coverage=True)
    atheris.instrument_all()
    atheris.Fuzz()

if __name__ == "__main__":
  main()
