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
  from google.protobuf.message import DecodeError, EncodeError

@atheris.instrument_func
def TestOneInput(input_bytes):
  """Test ParseFromString with bytes string"""
  pbmsg = test_full_pb2.TestMessSubMess()
  try:
    pbmsg.ParseFromString(input_bytes)
  except DecodeError:
    None

  try:
    pbmsg.SerializeToString()
  except EncodeError:
    None


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
