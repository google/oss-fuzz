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
#
##########################################################################
import sys
import atheris

import six
import json


@atheris.instrument_func
def TestOneInput(data):
  fdp = atheris.FuzzedDataProvider(data)
  val_1 = fdp.ConsumeUnicodeNoSurrogates(24)

  try:
    six.remove_move(val_1)
    six.u(fdp.ConsumeString(fdp.ConsumeIntInRange(1, 24)))
    six.ensure_text(fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(1,
                                                                         24)))
  except (AttributeError,):
    pass
  try:
    json_val = json.loads(
        fdp.ConsumeUnicodeNoSurrogates(fdp.ConsueIntInRange(1, 1024)))
  except:
    json_val = None

  if json_val != None:
    try:
      six.ensure_str(json_val)
      six.ensure_binary(json_val)
      six.ensure_text(json_val)
    except TypeError:
      pass

  try:
    six.ensure_str(data)
    six.ensure_binary(data)
    six.ensure_text(data)
  except (TypeError, UnicodeDecodeError):
    pass

  six.moves.html_parser.HTMLParser().unescape(
      fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(1, 1024)))


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
