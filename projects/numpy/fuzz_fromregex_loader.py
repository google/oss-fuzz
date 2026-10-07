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
import os
import re
import sys
import tempfile
from tokenize import TokenError
from zipfile import BadZipFile

with atheris.instrument_imports():
  import numpy as np

def TestOneInput(input_bytes):
  fdp = atheris.FuzzedDataProvider(input_bytes)
  input_str = fdp.ConsumeString(20)
  try:
    dtype = np.dtype(input_str)
  except (ValueError, TypeError, SyntaxError):
    return

  input_str = fdp.ConsumeString(20)
  try:
    reg = re.compile(input_str)
  except (ValueError, TypeError, re.error,OverflowError):
    return

  with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as fd:
      fd.write(fdp.ConsumeBytes(5000))
      tmpname = fd.name

  try:
    a = np.fromregex(tmpname, reg, dtype)
    if a.shape != (0,):
        print(a.shape)
  except OSError:
    return
  except TypeError:
    return
  except ValueError:
    return
  except EOFError:
    return
  finally:
    os.remove(tmpname)

def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
  atheris.Fuzz()

if __name__ == "__main__":
  main()
