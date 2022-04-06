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

with atheris.instrument_imports():
  import test_full_pb2
  from google.protobuf.message import DecodeError

@atheris.instrument_func
def TestOneInput(input_bytes):
  # We need to make the file an absolute path
  testfile_path = os.path.join(os.getcwd(), "serialized.bin")
  with open(testfile_path, "wb") as f:
    f.write(input_bytes)

  pbmsg = test_full_pb2.TestMessSubMess()
  with open(testfile_path, "rb") as fd:
    try:
      pbmsg.ParseFromString(fd.read())
    except DecodeError:
      None

  os.remove(testfile_path)


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
