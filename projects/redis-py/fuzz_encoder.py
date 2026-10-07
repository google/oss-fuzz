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
with atheris.instrument_imports():
    from redis.connection import *

def TestInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    encoder = Encoder("utf-8","ignore",True if fdp.ConsumeBool() else False)
    encoder.encode(fdp.ConsumeString(100))
    encoder.encode(fdp.ConsumeUnicode(100))
    encoder.encode(fdp.ConsumeBytes(100))
    encoder.encode(fdp.ConsumeInt(8))
    encoder.decode(fdp.ConsumeString(100))
    encoder.decode(fdp.ConsumeUnicode(100))
    encoder.decode(fdp.ConsumeBytes(100))
    encoder.decode(fdp.ConsumeInt(8))

    BaseParser().parse_error(fdp.ConsumeString(100))
    BaseParser().parse_error(fdp.ConsumeUnicode(100))

def main():
    atheris.Setup(sys.argv, TestInput, enable_python_coverage=True)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
