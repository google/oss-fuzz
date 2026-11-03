#!/usr/bin/python3

# Copyright 2026 Google LLC
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
import tempfile
import os

import atheris

with atheris.instrument_imports():
  import struct
  import xml.parsers.expat
  import xml.sax
  from fontTools.ttLib import TTFont, TTLibError

try:
  import lxml.etree
  _XML_ERRORS = (lxml.etree.Error,)
except ImportError:
  _XML_ERRORS = ()

_EXPECTED = (TTLibError, EOFError, struct.error, OverflowError, MemoryError,
             RecursionError, UnicodeDecodeError, xml.parsers.expat.ExpatError,
             xml.sax.SAXException) + _XML_ERRORS


@atheris.instrument_func
def TestOneInput(input_bytes):
  # importXML wants a real file path for its `<ttFont>` root checks.
  try:
    text = input_bytes.decode("utf-8")
  except UnicodeDecodeError:
    return

  font = TTFont(recalcBBoxes=False, recalcTimestamp=False)
  with tempfile.NamedTemporaryFile(mode="w",
                                   suffix=".ttx",
                                   delete=False,
                                   encoding="utf-8") as fp:
    fp.write(text)
    path = fp.name
  try:
    try:
      font.importXML(path)
    except _EXPECTED:
      return
    # Whatever imported should compile back to a binary without leaving
    # the documented error space.
    out = io.BytesIO()
    try:
      font.save(out)
    except _EXPECTED:
      return
  finally:
    os.unlink(path)


def main():
  atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
