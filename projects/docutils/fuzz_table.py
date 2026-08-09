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

from docutils import ApplicationError
from docutils.parsers.rst import tableparser
from docutils.statemachine import StringList, string2lines


def TestOneInput(data):
  fdp = atheris.FuzzedDataProvider(data)
  parser = tableparser.GridTableParser()
  lines_input = StringList(
      string2lines(fdp.ConsumeUnicodeNoSurrogates(sys.maxsize)), 'fuzz data')
  if len(lines_input) < 1:
    return
  parser.setup(lines_input)
  try:
    parser.find_head_body_sep()
    parser.parse_table()
  except ApplicationError:
    pass


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
