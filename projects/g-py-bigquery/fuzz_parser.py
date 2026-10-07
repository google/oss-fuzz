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
import IPython

with atheris.instrument_imports():
  from google.cloud.bigquery.magics.line_arg_parser.lexer import Lexer
  from google.cloud.bigquery.magics.line_arg_parser.parser import Parser
  from google.cloud.bigquery.magics.line_arg_parser.parser import ParseError
  from google.cloud.bigquery.magics.line_arg_parser.parser import QueryParamsParseError

def TestOneInput(data):
  fdp = atheris.FuzzedDataProvider(data)
  s1 = fdp.ConsumeString(sys.maxsize)

  tokens = list(Lexer(s1))
  if len(tokens) == 0:
    return

  lexer = Lexer(s1)
  parser = Parser(lexer)
  try:
    parser.input_line()
  except ParseError:
    pass

  lexer = Lexer(s1)
  parser = Parser(lexer)
  try:
    parser.collection_items()
  except QueryParamsParseError:
    pass

  lexer = Lexer(s1)
  parser = Parser(lexer)
  try:
    parser.dict_items()
  except QueryParamsParseError:
    pass

def main():
  atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
  atheris.Fuzz()

if __name__ == "__main__":
  main()
