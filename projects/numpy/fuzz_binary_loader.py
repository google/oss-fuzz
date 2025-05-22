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
import sys
import tempfile
from tokenize import TokenError
from zipfile import BadZipFile

with atheris.instrument_imports():
  import numpy as np

def TestOneInput(input_bytes):
  with tempfile.NamedTemporaryFile(suffix=".npy", delete=False) as fd:
      fdp = atheris.FuzzedDataProvider(input_bytes)
      fd.write(fdp.ConsumeBytes(sys.maxsize))
      tmpname = fd.name

  try:
    np.load(tmpname)
  # Catch all of the exceptions that are documented in help(np.load)
  except OSError:
    return
  except ValueError:
    return
  except EOFError:
    return
  except IndentationError:
    return
  except BadZipFile:
    return
  except TokenError:
    return
  finally:
    os.remove(tmpname)

def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
  atheris.Fuzz()

if __name__ == "__main__":
  main()
