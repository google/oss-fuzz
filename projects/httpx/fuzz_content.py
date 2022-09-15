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

import asyncio

with atheris.instrument_imports():
    from httpx._content import encode_request


async def fuzz_bytes_content(data):
    _, stream = encode_request(content=data)

    sync_content = b"".join([part for part in stream])
    async_content = b"".join([part async for part in stream])

    assert sync_content == data
    assert async_content == data


async def fuzz_multipart_files_content(data):
    files = {"files": io.BytesIO(data)}
    _, stream = encode_request(files=files, boundary=b"+++")

    sync_content = b"".join([part for part in stream])
    async_content = b"".join([part async for part in stream])

    assert sync_content == b"".join(
        [
            b"--+++\r\n",
            b'Content-Disposition: form-data; name="files"; filename="upload"\r\n',
            b"Content-Type: application/octet-stream\r\n",
            b"\r\n",
            data + b"\r\n",
            b"--+++--\r\n",
        ]
    )

    assert async_content == b"".join(
        [
            b"--+++\r\n",
            b'Content-Disposition: form-data; name="files"; filename="upload"\r\n',
            b"Content-Type: application/octet-stream\r\n",
            b"\r\n",
            data + b"\r\n",
            b"--+++--\r\n",
        ]
    )


def TestOneInput(data):
    try:
        asyncio.run(fuzz_bytes_content(data))
        asyncio.run(fuzz_multipart_files_content(data))
    except TypeError:
        return


def main():
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    loop = asyncio.get_event_loop()
    asyncio.set_event_loop(loop)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
