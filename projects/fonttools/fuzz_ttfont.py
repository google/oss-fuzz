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

import atheris

with atheris.instrument_imports():
  import struct
  import zlib
  from fontTools.misc.xmlWriter import XMLWriter
  from fontTools.ttLib import TTFont, TTLibError

try:
  import brotli
  _BROTLI_ERRORS = (brotli.error,)
except ImportError:
  _BROTLI_ERRORS = ()

# Errors that are expected on malformed font input. Anything else
# (IndexError, ValueError, AttributeError, ...) is allowed to crash the
# fuzzer: those are the decompile bugs we are looking for.
_EXPECTED = (TTLibError, EOFError, struct.error, OverflowError, MemoryError,
             RecursionError, UnicodeDecodeError, zlib.error) + _BROTLI_ERRORS


@atheris.instrument_func
def TestOneInput(input_bytes):
  font_file = io.BytesIO(input_bytes)
  try:
    # TTFont auto-detects SFNT (TTF/OTF), WOFF and WOFF2 from the leading
    # bytes, so one entry point covers all binary flavors.
    font = TTFont(font_file, lazy=True)
  except _EXPECTED:
    return

  # Force decompilation of every table the directory advertises. Lazy
  # loading defers the interesting parsing work until here.
  for tag in font.keys():
    try:
      table = font[tag]
      if hasattr(table, "decompile"):
        table.toXML(XMLWriter(io.BytesIO()), font)
    except _EXPECTED:
      continue


def main():
  atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
