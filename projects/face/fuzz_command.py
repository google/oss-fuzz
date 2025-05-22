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

import face


def empty():
  return


def TestOneInput(data):
  fdp = atheris.FuzzedDataProvider(data)
  args = []
  for idx in range(fdp.ConsumeIntInRange(1, 100)):
    args.append(fdp.ConsumeUnicodeNoSurrogates(124))

  cmd = face.Command(empty, name='fuzz')
  for idx in range(fdp.ConsumeIntInRange(1, 15)):
    try:
      cmd.add(fdp.ConsumeUnicodeNoSurrogates(64),
              char=fdp.ConsumeUnicodeNoSurrogates(5),
              parse_as=fdp.ConsumeBool(),
              doc=fdp.ConsumeUnicodeNoSurrogates(64))
    except face.errors.FaceException:
      pass
    except ValueError:
      # Raised by face: https://github.com/mahmoud/face/blob/eb56873b9081852f4500b1a61f178ca0cc8666bc/face/utils.py#L80
      pass

  # Create a command and parse the args
  try:
    cmd.parse(args)
  except face.errors.FaceException:
    pass


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
