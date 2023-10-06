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

import io
import sys
import atheris
import brotli

from fontTools import ttLib
from fontTools.ttLib import TTFont
from fontTools.ttLib.woff2 import WOFF2Reader
import xml


def TestOneInput(data):
  try:
    WOFF2Reader(io.BytesIO(data))
  except ttLib.TTLibError:
    pass
  except AssertionError:
    pass
  except ImportError:
    pass
  except brotli.error:
    pass


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
