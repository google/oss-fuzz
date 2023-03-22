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

import atheris

import sys
import pygments
from pygments.formatters import *
import pygments.lexers

# pygments.LEXERS.values() is a list of tuples like this, with some of then empty:
# (textual class name, longname, tuple of aliases, tuple of filename patterns, tuple of mimetypes)
LEXERS = [l[2][0] for l in pygments.lexers.LEXERS.values() if l[2]]
FORMATTERS = [BBCodeFormatter(), GroffFormatter(), HtmlFormatter(),
              IRCFormatter(), LatexFormatter(), NullFormatter(),
              PangoMarkupFormatter(), RawTokenFormatter(), RtfFormatter(),
              SvgFormatter(), Terminal256Formatter(), TerminalFormatter(),
              TerminalTrueColorFormatter()]


def TestOneInput(data: bytes) -> int:
  fdp = atheris.FuzzedDataProvider(data)
  random_lexer = pygments.lexers.get_lexer_by_name(fdp.PickValueInList(LEXERS))
  formatter = fdp.PickValueInList(FORMATTERS)
  str_data = fdp.ConsumeUnicode(atheris.ALL_REMAINING)

  pygments.highlight(str_data, random_lexer, formatter)
  return 0


atheris.instrument_all()
atheris.Setup(sys.argv, TestOneInput)
atheris.Fuzz()
