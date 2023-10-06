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

from distlib import DistlibException
from distlib.compat import StringIO
from distlib.metadata import (LegacyMetadata, Metadata)


def TestOneInput(data):
  fdp = atheris.FuzzedDataProvider(data)
  try:
    metadata = LegacyMetadata()
    metadata.read_file(StringIO(fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 1024))))
  except ValueError:
    # ValueErrors are raised varies places, e.g.
    # https://github.com/pypa/distlib/blob/05375908c1b2d6b0e74bdeb574569d3609db9f56/distlib/version.py#L106
    pass
  except SyntaxError:
    pass

  try:
    metadata = Metadata(fileobj=StringIO(fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 1024))))
  except ValueError:
    # ValueErrors are raised varies places, e.g.
    # https://github.com/pypa/distlib/blob/05375908c1b2d6b0e74bdeb574569d3609db9f56/distlib/version.py#L106
    pass
  except SyntaxError:
    pass
  except DistlibException:
    pass


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
