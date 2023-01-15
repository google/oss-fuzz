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

import click
from click.parser import OptionParser
from click import exceptions


def TestOneInput(data):
  fdp = atheris.FuzzedDataProvider(data)

  # Create a parser we can fuzz.
  # This can be extended further by creating logic that will create arbitrary
  # parser.
  ctx = click.Context(click.Command("fuzz"))
  parser = OptionParser(ctx)
  click.Option("+z", is_flag=True).add_to_parser(parser, ctx)
  click.Option("-b", is_flag=False).add_to_parser(parser, ctx)
  click.Option("+c", multiple=fdp.ConsumeBool()).add_to_parser(parser, ctx)
  click.Option("-d", default="abc").add_to_parser(parser, ctx)
  click.Option("+e", type=int).add_to_parser(parser, ctx)
  click.Option("-f", type=click.Choice(["option1", "option2"])).add_to_parser(parser, ctx)
  click.Option("!g", type=click.Choice(["option1", "option2"])).add_to_parser(parser, ctx)
  click.Option("!h", default="abcd").add_to_parser(parser, ctx)
  
  args = []
  for idx in range(fdp.ConsumeIntInRange(1, 15)):
    args.append(fdp.ConsumeUnicodeNoSurrogates(64))
  try:
    parser.parse_args(args)
  except exceptions.ClickException:
    pass


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
