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

class FuzzEnum(enum.Enum):
    VAL1 = 1
    VAL2 = 2

def TestOneInput(data):
    """Hits the logic in https://github.com/abseil/abseil-py/tree/main/absl/flags"""
    fdp = atheris.FuzzedDataProvider(data)
    
    def rs(size):
        return fdp.ConsumeUnicodeNoSurrogates(size)

    fuzz_flag_values = flags.FlagValues()

    # Generate random valid/invalid flag names and helpers
    try:
        flags.DEFINE_string(rs(256), None, rs(256), flag_values=fuzz_flag_values)
    except (_exceptions.Error, ValueError, TypeError):
        pass

    try:
        flags.DEFINE_float(rs(256), fdp.ConsumeFloat(), rs(256), flag_values=fuzz_flag_values)
    except (_exceptions.Error, ValueError, TypeError):
        pass

    try:
        flags.DEFINE_enum_class(rs(256), None, FuzzEnum, rs(256), flag_values=fuzz_flag_values)
    except (_exceptions.Error, ValueError, TypeError):
        pass

    try:
        # FIXED: Pass a fuzzed integer or None as default value, not a string
        default_int = fdp.ConsumeInt(4) if fdp.ConsumeBool() else None
        flags.DEFINE_integer(rs(256), default_int, rs(256), flag_values=fuzz_flag_values)
    except (_exceptions.Error, ValueError, TypeError):
        pass

    # Generate mock command line arguments
    command_line_args = []
    for _ in range(fdp.ConsumeIntInRange(1, 20)):
        command_line_args.append(rs(256))

    # Parse and validate the arguments
    try:
        fuzz_flag_values(command_line_args)
    except (_exceptions.Error, ValueError, TypeError):
        pass

def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
