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
import atheris
import traceback
from prompt_toolkit.contrib.regular_languages import compile as fuzz_target


def TestOneInput(data):
  fdp = atheris.FuzzedDataProvider(data)
  try:
    fuzz_target(fdp.ConsumeUnicodeNoSurrogates(sys.maxsize))
  except AssertionError:
    pass
  except Exception as e:
    tb = ''.join(traceback.TracebackException.from_exception(e).format())
    if "parse_regex" in tb:
      # The parse_regex function throws a set of exceptions of Exception type,
      # we do not care about these.
      pass
    else:
      raise e


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
