#!/usr/bin/python3
# Copyright 2022 Google LLC
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

import os
import sys
import atheris

with atheris.instrument_imports(enable_loader_override=False):
  from xdg import Mime
  from xdg.Exceptions import ParsingError

@atheris.instrument_func
def TestOneInput(input_bytes):
  # We need to make the file an absolute path
  testfile_path = os.path.join(os.getcwd(), "testfile.tmp")
  with open(testfile_path, "wb") as f:
    f.write(input_bytes)

  # Test basic Mime API
  Mime.get_type2(testfile_path)
  Mime.get_type_by_contents(testfile_path)
  Mime.get_type_by_data(input_bytes)

  # Test GlobDB
  globs = Mime.GlobDB()
  try:
    globs.merge_file(testfile_path)
    globs.merge_file(testfile_path)
  except UnicodeError as e:
    pass
  except ValueError as e:
    if (
        "not enough values to unpack" in str(e) or
        "invalid literal for int" in str(e)
    ):
      pass
    else:
      raise e

  # Test MagicDB
  magic = Mime.MagicDB()
  try:
    magic.merge_file(testfile_path)
    magic.finalise()
  except UnicodeDecodeError:
    pass
  except (OSError, ValueError) as e:
    msg = str(e)
    if (
      "Not a MIME magic file" in msg or
      "Malformed section heading" in msg
    ):
      pass
    else:
      raise e

  # Cleanup
  os.remove(testfile_path)


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
