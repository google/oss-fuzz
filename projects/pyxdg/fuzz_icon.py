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
import shutil
import atheris

with atheris.instrument_imports(enable_loader_override=False):
  from xdg.IconTheme import IconTheme, getIconPath, getIconData 
  from xdg.Exceptions import ParsingError

@atheris.instrument_func
def TestOneInput(input_bytes):
  # We need to make the file an absolute path
  testfile_path = os.path.join(os.getcwd(), "testfile.theme")
  with open(testfile_path, "wb") as f:
    f.write(input_bytes)

  th = IconTheme()
  try:
    th.parse(testfile_path)
    th.validate()
    dst_file = os.path.join(os.getcwd(), "testicon.icon")
    shutil.move(testfile_path, dst_file)
    getIconData(dst_file)
  except ParsingError:
    pass
  os.remove(testfile_path)


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
