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
import simplejson


def TestOneInput(data):
  fdp = atheris.FuzzedDataProvider(data)
  original = fdp.ConsumeUnicodeNoSurrogates(sys.maxsize)
  encoder = simplejson.JSONEncoder()
  try:
    # Anything that can be decoded shold be able to be encoded
    encoder.encode(simplejson.loads(original))
  except simplejson.JSONDecodeError:
    pass
  except RecursionError:
    pass
  return


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
