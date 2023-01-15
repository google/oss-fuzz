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

import sys
import enum
import atheris

from absl import flags
from absl.flags import _exceptions
from absl.flags import argparse_flags

class FuzzEnum(enum.Enum):
  VAL1 = object()
  VAL2 = object()


def TestOneInput(data):
  """Hits the logic in https://github.com/abseil/abseil-py/tree/main/absl/flags"""
  fdp = atheris.FuzzedDataProvider(data)

  def rs(size):
    return fdp.ConsumeUnicodeNoSurrogates(size)

  fuzz_flag_values = flags.FlagValues()
  try:
    flags.DEFINE_string(rs(256), None, rs(256), flag_values = fuzz_flag_values)
  except _exceptions.Error:
    pass

  try:
    flags.DEFINE_float(rs(256), 0.0, rs(256), flag_values = fuzz_flag_values)
  except _exceptions.Error:
    pass

  try:
    flags.DEFINE_enum_class(rs(256), None, FuzzEnum, rs(256), flag_values = fuzz_flag_values)
  except _exceptions.Error:
    pass

  try:
    flags.DEFINE_integer(rs(256), rs(256), rs(256), flag_values = fuzz_flag_values)
  except _exceptions.Error:
    pass
  
  command_line_args = []
  for idx in range(fdp.ConsumeIntInRange(1, 20)):
    command_line_args.append(rs(256))

  # Parse it all
  try:
    fuzz_flag_values(command_line_args)
  except _exceptions.Error:
    pass


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
