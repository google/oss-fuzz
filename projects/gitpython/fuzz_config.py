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
import atheris
import sys
import io
from configparser import MissingSectionHeaderError, ParsingError

with atheris.instrument_imports():
  from git import GitConfigParser


def TestOneInput(data):
  sio = io.BytesIO(data)
  sio.name = "/tmp/fuzzconfig.config"
  git_config = GitConfigParser(sio)
  try:
    git_config.read()
  except (MissingSectionHeaderError, ParsingError, UnicodeDecodeError):
    return -1  # Reject inputs raising expected exceptions
  except (IndexError, ValueError) as e:
    if isinstance(e, IndexError) and "string index out of range" in str(e):
      # Known possibility that might be patched
      # See: https://github.com/gitpython-developers/GitPython/issues/1887
      pass
    elif isinstance(e, ValueError) and "embedded null byte" in str(e):
      # The `os.path.expanduser` function, which does not accept strings
      # containing null bytes might raise this.
      return -1
    else:
      raise e  # Raise unanticipated exceptions as they might be bugs


def main():
  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
