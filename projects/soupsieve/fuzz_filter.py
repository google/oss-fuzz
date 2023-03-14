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

from bs4 import BeautifulSoup
import unittest
import soupsieve as sv


def TestOneInput(data):
  fdp = atheris.FuzzedDataProvider(data)
  html_str = fdp.ConsumeUnicodeNoSurrogates(1024)

  try:
    the_soup = BeautifulSoup(html_str, 'html.parser')
  except:
    # We do not want to deal with any errors in BeautifulSoup
    return

  try:
    sv.filter(fdp.ConsumeUnicodeNoSurrogates(24), the_soup)
  except sv.util.SelectorSyntaxError:
    pass
  sv.purge()


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
