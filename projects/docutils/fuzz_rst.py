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

from docutils.parsers.rst import Parser
from docutils.frontend import get_default_settings
from docutils.utils import new_document
from docutils import nodes
from docutils import ApplicationError
from docutils.parsers.rst import tableparser
from docutils.statemachine import StringList, string2lines
from docutils.transforms.universal import (SmartQuotes, TestMessages,
                                           Decorations, ExposeInternals,
                                           Messages, FilterMessages,
                                           StripComments,
                                           StripClassesAndElements)


def TestOneInput(data):
  fdp = atheris.FuzzedDataProvider(data)
  parser = Parser()
  settings = get_default_settings(Parser)
  settings.warning_stream = ""
  settings.smart_quotes = fdp.ConsumeBool()
  settings.trim_footnote_ref_space = fdp.ConsumeBool()
  settings.report = fdp.ConsumeIntInRange(0, 5)

  doc = new_document(fdp.ConsumeUnicodeNoSurrogates(64), settings.copy())
  try:
    parser.parse(fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 2048)), doc)
    if fdp.ConsumeBool():
      doc.transformer.add_transforms([TestMessages])
    if fdp.ConsumeBool():
      doc.transformer.add_transform(SmartQuotes)
    if fdp.ConsumeBool():
      doc.transformer.add_transform(Decorations)
    if fdp.ConsumeBool():
      doc.transformer.add_transform(ExposeInternals)
    if fdp.ConsumeBool():
      doc.transformer.add_transform(Messages)
    if fdp.ConsumeBool():
      doc.transformer.add_transform(FilterMessages)
    if fdp.ConsumeBool():
      doc.transformer.add_transform(StripComments)
    if fdp.ConsumeBool():
      doc.transformer.add_transform(StripClassesAndElements)
    doc.transformer.apply_transforms()
    o = doc.pformat()

    visitor = nodes.TreeCopyVisitor(doc)
    doc.walkabout(visitor)
    newtree = visitor.get_tree_copy()
  except ApplicationError:
    pass


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
