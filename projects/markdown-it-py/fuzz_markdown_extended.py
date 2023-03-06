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

# Beautified from auto-generated fuzzer at:
# https://github.com/ossf/fuzz-introspector/pull/872#issuecomment-1450847118
# Auto-fuzz heuristics used: py-autofuzz-heuristics-4.1
# Imports by the generated code
import markdown_it

def TestOneInput(data):
  fdp = atheris.FuzzedDataProvider(data)
  val_1 = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 1024))
  val_2 = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 1024))
  val_3 = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 256))
  val_4 = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 256))
  val_5 = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 256))
  val_6 = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 256))
  val_7 = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 256))
  val_8 = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 256))
  val_9 = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 256))
  val_10 = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 256))

  try:
    c1 = markdown_it.main.MarkdownIt()
    c1.render(val_1)
    c1.parse(val_2)
    c1.renderInline(val_3)
    c1.parseInline(val_4)
    c1.normalizeLink(val_5)
    c1.normalizeLinkText(val_6)
    c1.disable(val_7)
    c1.enable(val_8)
    c1.validateLink(val_9)
    c1.configure(val_10)
  except(ValueError,KeyError,TypeError,):
    # Exceptions thrown by the hit code.
    pass


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
