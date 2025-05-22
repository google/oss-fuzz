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
#
##########################################################################
"""Fuzzer directly targetting the native extensions."""
import sys
import atheris

import psutil
from psutil import _psutil_linux as cext_linux
from psutil import _psutil_posix as cext_posix


def TestOneInput(data):
  fdp = atheris.FuzzedDataProvider(data)
  try:
    cext_linux.proc_cpu_affinity_get(fdp.ConsumeIntInRange(1, sys.maxsize))
  except psutil._compat.ProcessLookupError:
    pass
  try:
    cext_linux.net_if_duplex_speed(
        fdp.ConsumeString(fdp.ConsumeIntInRange(1, 2048)))
  except (OSError, ValueError):
    pass

  try:
    cext_posix.net_if_mtu(fdp.ConsumeString(fdp.ConsumeIntInRange(1, 4096)))
  except (OSError, ValueError):
    pass
  try:
    cext_posix.net_if_flags(fdp.ConsumeString(fdp.ConsumeIntInRange(1, 4096)))
  except (OSError, ValueError):
    pass
  try:
    cext_posix.getpriority(fdp.ConsumeIntInRange(1, sys.maxsize))
  except (OSError, ValueError):
    pass

  try:
    list(
        psutil.process_iter([
            fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(1, 4096)),
            fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(1, 4096))
        ]))
  except ValueError:
    pass


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
