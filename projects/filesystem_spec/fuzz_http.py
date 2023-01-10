#!/usr/bin/python3
# Copyright 2023 Google LLC
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
import pathlib

from fsspec.implementations import http
import fsspec
from fsspec.exceptions import FSTimeoutError

# Import aiohttp and requests for pyinstaller
from requests import *
from aiohttp import *
from aiohttp.client_exceptions import ClientError


@atheris.instrument_func
def TestOneInput(data):
  fdp = atheris.FuzzedDataProvider(data)

  path = fdp.ConsumeUnicodeNoSurrogates(124)

  # Ensure it's a file vs directory
  path = path + "the_file.txt"
  h = fsspec.filesystem("http", use_listings_cache=True)
  tmp_path = pathlib.Path(path)
  try:
    tmp_path.write_bytes(data)
  except:
    # Don't care about errors in pathlib
    try:
      tmp_path.unlink()
    except:
      pass
    return

  try:
    h.put_file(tmp_path, path, method="put", timeout=0.5)
  except FSTimeoutError:
    try:
      tmp_path.unlink()
    except:
      pass
    return
  except (
    ClientError,
    TypeError,
    AssertionError
  ) as e:
    # Abandon if aiohttp threw an error.
    try:
      tmp_path.unlink()
    except:
      pass
    return

  # Reading the file should be possible now.
  with h.open(path) as http_f:
    http_f.read()

  try:
    tmp_path.unlink()
  except:
    pass


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
