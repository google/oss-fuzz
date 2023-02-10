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

# aiohttp imports
import asyncio
with atheris.instrument_imports():
    import aiohttp
    from aiohttp.test_utils import make_mocked_request
    from multidict import CIMultiDict
    from yarl import URL

@atheris.instrument_func
async def fuzz_run_one_async(data):
    fdp = atheris.FuzzedDataProvider(data)
    url_s = fdp.ConsumeString(sys.maxsize)
    try:
        URL(url_s)
    except Exception:
        return

    headers = CIMultiDict(
        { fdp.ConsumeString(20) : fdp.ConsumeString(sys.maxsize) }
    )
    req = make_mocked_request("GET", url_s, headers=headers)

    l1 = len(req.forwarded)
    ret = await req.post()

@atheris.instrument_func
def TestOneInput(data):
    asyncio.run(fuzz_run_one_async(data))

def main():
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    loop = asyncio.get_event_loop()
    asyncio.set_event_loop(loop)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
