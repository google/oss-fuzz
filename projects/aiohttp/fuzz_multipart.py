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

import io
import sys
import atheris

# aiohttp imports
import asyncio
with atheris.instrument_imports():
    import aiohttp
    from aiohttp.hdrs import (
        CONTENT_TYPE,
    )

class FuzzStream:
    def __init__(self, content):
        self.content = io.BytesIO(content)

    async def read(self, size = None):
        return self.content.read(size)

    def at_eof(self):
        return self.content.tell() == len(self.content.getbuffer())

    async def readline(self):
        return self.content.readline()

    def unread_data(self, data):
        self.content = io.BytesIO(data + self.content.read())


@atheris.instrument_func
async def fuzz_bodypart_reader(data):
    newline=b'\n'
    fdp = atheris.FuzzedDataProvider(data)
    obj = aiohttp.BodyPartReader(
        b"--:",
        {
            CONTENT_TYPE: fdp.ConsumeUnicode(30)
        },
        FuzzStream(fdp.ConsumeBytes(atheris.ALL_REMAINING)),
        _newline=newline
    )
    if not obj.at_eof():
        await obj.form()

@atheris.instrument_func
def TestOneInput(data):
    try:
        asyncio.run(fuzz_bodypart_reader(data))
    except AssertionError:
        return

def main():
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    loop = asyncio.get_event_loop()
    asyncio.set_event_loop(loop)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
