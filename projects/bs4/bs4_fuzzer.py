#!/usr/bin/python3

# Copyright 2020 Google LLC
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

with atheris.instrument_imports():
  import logging
  import warnings
  from bs4 import BeautifulSoup


try:
  import HTMLParser
  HTMLParseError = HTMLParser.HTMLParseError
except ImportError:
  # HTMLParseError is removed in Python 3.5. Since it can never be
  # thrown in 3.5, we can just define our own class as a placeholder.

  class HTMLParseError(Exception):
    pass


@atheris.instrument_func
def TestOneInput(data):
  """TestOneInput gets random data from the fuzzer, and throws it at bs4."""
  if len(data) < 1:
    return

  parsers = ['lxml-xml', 'html5lib', 'html.parser', 'lxml']
  try:
    idx = int(data[0]) % len(parsers)
  except ValueError:
    return

  try:
    soup = BeautifulSoup(data[1:], features=parsers[idx])
  except HTMLParseError:
    return
  except ValueError:
    return

  list(soup.find_all(True))
  soup.prettify()


def main():
  logging.disable(logging.CRITICAL)
  warnings.filterwarnings('ignore')
  atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
