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

import sys
import atheris

import pip._internal.req.req_file as pipreq
from pip._internal.exceptions import RequirementsFileParseError
from pip._internal.network.session import PipSession


@atheris.instrument_func
def TestOneInput(input_bytes):
  with open("temp.req", "wb") as fd:
      fd.write(input_bytes)
  try:
    [_ for _ in pipreq.parse_requirements(
      "temp.req",
      PipSession(),
      finder=None,
      options=None,
      constraint=None
    )]
  except UnicodeDecodeError:
    # Catch this because I think it's a user issue if Unicode exceptions happen
    None
  except RequirementsFileParseError:
    # Exception thrown by the requirements reader
    None


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
