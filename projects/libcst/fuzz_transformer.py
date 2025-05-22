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

import libcst
from libcst import parse_module
from libcst import PartialParserConfig, ParserSyntaxError
from libcst.codemod._context import CodemodContext
from libcst.codemod._runner import SkipFile
from libcst.codemod.commands.unnecessary_format_string import UnnecessaryFormatString

def TestOneInput(data):
  fdp = atheris.FuzzedDataProvider(data)

  context = CodemodContext()
  transform_instance = UnnecessaryFormatString(context)
  inp = fdp.ConsumeUnicodeNoSurrogates(sys.maxsize)
  try:
    input_tree = parse_module(
      inp,
      config=PartialParserConfig()
    )
    try:
      output_tree = transform_instance.transform_module(input_tree)
    except SkipFile:
      pass
  except ParserSyntaxError:
    pass
  except RecursionError:
    pass


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
