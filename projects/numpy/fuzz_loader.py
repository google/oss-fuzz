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
  from io import StringIO
  import numpy as np

def get_fuzz_types():
    # Define the rows
    dtype = np.dtype(
        [('f0', np.uint16), ('f1', np.float64), ('f2', 'S7'), ('f3', np.int8)]
    )

    # An expected match
    expected = np.array(
        [
            (1, 2.4, "a", -34),
            (2, 3.1, "b", 29),
            (3, 9.9, "g", 120),
        ],
        dtype=dtype
    )
    return dtype, expected

def TestOneInput(fuzz_data):
  dtype, expected = get_fuzz_types()
  fdp = atheris.FuzzedDataProvider(fuzz_data)
  new_data = StringIO(fdp.ConsumeString(sys.maxsize))
  try:
    np.loadtxt(new_data, dtype=dtype, delimiter=";", skiprows=True)
  # Catch all of the exceptions that are caught in 
  # https://github.com/numpy/numpy/blob/main/numpy/lib/tests/test_loadtxt.py
  except StopIteration:
    return
  except ValueError:
    return
  except IndexError:
    return
  except TypeError:
    return
  except RuntimeError:
    return

def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
  atheris.Fuzz()

if __name__ == "__main__":
  main()
