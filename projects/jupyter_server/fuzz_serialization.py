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

import atheris
import sys

with atheris.instrument_imports():
  from jupyter_client.session import Session
  from jupyter_server.base.zmqhandlers import (
    deserialize_binary_message,
    serialize_binary_message,
  )


def TestOneInput(data):
  fdp = atheris.FuzzedDataProvider(data)
  s1 = fdp.ConsumeString(50)
  s2 = fdp.ConsumeString(50)
  if len(s1) == 0 or len(s2) == 0:
    return
  s = Session()
  msg = s.msg("data_pub", content={s1: s2})
  msg["buffers"] = [
    memoryview(fdp.ConsumeBytes(5)),
    memoryview(fdp.ConsumeBytes(5)),
    memoryview(fdp.ConsumeBytes(5))
  ]
  bmsg = serialize_binary_message(msg)
  msg2 = deserialize_binary_message(bmsg)
  assert msg2 == msg


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
  atheris.Fuzz()

if __name__ == "__main__":
  main()
