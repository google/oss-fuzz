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
import io

# All code is instrumented by calling atheris.instrument_all below
from google.resumable_media import _upload

def test_simple(data):
  upload = _upload.SimpleUpload("localhost:8008/index.html")
  upload._prepare_request(data, None)

def test_multipart(data):
  fdp = atheris.FuzzedDataProvider(data)
  headers = {"spin": "doctors"}
  upload = _upload.MultipartUpload(
    "localhost:8008/index.html",
    headers=headers,
    checksum="md5"
  )
  try:
    upload._prepare_request(
      fdp.ConsumeBytes(200),
      {},
      fdp.ConsumeString(200)
    )
  except UnicodeEncodeError:
    pass

def _upload_in_flight(data, headers=None, checksum=None):
  upload = _upload.ResumableUpload(
    "localhost:8008://heyo",
    1024 * 1024,
    headers=headers,
    checksum=checksum
  )
  upload._stream = io.BytesIO(data)
  upload._content_type = "text/plain"
  upload._total_bytes = len(data)
  upload._resumable_url = "localhost:8009/test.invalid?upload_id=not-none"
  return upload


def test_checksum(data):
  fdp = atheris.FuzzedDataProvider(data)
  for cs in ["md5", "crc32"]:
    upload = _upload_in_flight(fdp.ConsumeBytes(200), checksum=cs)
    try:
      start_byte, payload, _ = _upload.get_next_chunk(
        upload._stream,
        fdp.ConsumeIntInRange(1, 250),
        fdp.ConsumeIntInRange(1, 250)
      )
    except ValueError:
      pass
  

def TestOneInput(data):
  test_simple(data)
  test_multipart(data)
  test_checksum(data)

def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
  atheris.Fuzz()

if __name__ == "__main__":
  main()
