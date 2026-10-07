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

import wtforms


class FuzzField:
  def __init__(self, text):
    self.text = text
    self.data = text

  def gettext(self, string):
    return self.text


def TestOneInput(data):
  fdp = atheris.FuzzedDataProvider(data)

  try:
    c1 = wtforms.validators.HostnameValidation()
    c1(fdp.ConsumeUnicodeNoSurrogates(1024))
  except (wtforms.validators.StopValidation,
          wtforms.validators.ValidationError):
    pass

  try:
    validator = wtforms.validators.URL()
    validator(fdp.ConsumeUnicodeNoSurrogates(1024),
              FuzzField(fdp.ConsumeUnicodeNoSurrogates(1024)))
  except wtforms.validators.ValidationError:
    pass

  try:
    validator = wtforms.validators.email()
    validator(fdp.ConsumeUnicodeNoSurrogates(1024),
              FuzzField(fdp.ConsumeUnicodeNoSurrogates(1024)))
  except wtforms.validators.ValidationError:
    pass


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
