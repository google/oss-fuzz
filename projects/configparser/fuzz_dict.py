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

import json
from backports import configparser


def TestOneInput(data):
  fdp = atheris.FuzzedDataProvider(data)
  try:
    json_dict = json.loads(fdp.ConsumeUnicodeNoSurrogates(sys.maxsize))
  except:
    return
  if not isinstance(json_dict, dict):
    return

  config_parser = configparser.ConfigParser()
  try:
    config_parser.read_dict(json_dict)
  except (configparser.Error):
    pass
  except ValueError:
    # Thrown at: https://github.com/jaraco/configparser/blob/8b5181b4f270be88f3e4572300406587fdbd4a6e/src/backports/configparser/__init__.py#L422
    pass


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
