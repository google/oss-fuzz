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
import sys
import io
import atheris
import nbformat


def TestOneInput(data):
  fdp = atheris.FuzzedDataProvider(data)
  notebook_in_mem = io.StringIO(fdp.ConsumeUnicodeNoSurrogates(32768))
  for version in range(1, 5):
    try:
      nbformat.read(notebook_in_mem, as_version=version)
    except nbformat.reader.NotJSONError:
      pass
    except nbformat.NBFormatError:
      pass
    except nbformat.validator.ValidationError:
      pass
    except AttributeError:
      pass


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
