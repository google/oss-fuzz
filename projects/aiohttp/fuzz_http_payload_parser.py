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

# aiohttp imports
import asyncio
with atheris.instrument_imports():
    import aiohttp
    from aiohttp.base_protocol import BaseProtocol
    from aiohttp import http_exceptions, streams

@atheris.instrument_func
def TestOneInput(data):
    loop = asyncio.get_event_loop()
    pr = BaseProtocol(loop)
    out = aiohttp.StreamReader(pr, 2**16, loop=None)
    h_p = aiohttp.http_parser.HttpPayloadParser(out, loop, 32768)
    try:
        h_p.feed_data(data)
    except aiohttp.http_exceptions.HttpProcessingError:
        None

def main():
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    loop = asyncio.get_event_loop()
    asyncio.set_event_loop(loop)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
