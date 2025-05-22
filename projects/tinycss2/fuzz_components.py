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
import tinycss2


def TestOneInput(data):
  fdp = atheris.FuzzedDataProvider(data)

  skip_comments = fdp.ConsumeBool()
  skip_whitespace = fdp.ConsumeBool()
  source_to_parse = fdp.ConsumeUnicodeNoSurrogates(sys.maxsize)

  tinycss2.parse_one_component_value(
    source_to_parse,
    skip_comments
  )

  tinycss2.parse_one_component_value(
    source_to_parse,
    skip_comments
  )

  tinycss2.parse_declaration_list(
    source_to_parse,
    skip_comments,
    skip_whitespace
  )

  tinycss2.parse_one_rule(
    source_to_parse,
    skip_comments,
  )

  tinycss2.parse_rule_list(
    source_to_parse,
    skip_comments,
    skip_whitespace
  )

  tinycss2.parse_stylesheet(
    source_to_parse,
    skip_comments,
    skip_whitespace
  )


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
