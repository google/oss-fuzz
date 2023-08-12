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
################################################################################
import sys
from enum import IntEnum

import atheris

with atheris.instrument_imports(include=["pyvex"]):
    import pyvex

# Additional imports
import archinfo
from contextlib import contextmanager
from io import StringIO

from enhanced_fdp import EnhancedFuzzedDataProvider


@contextmanager
def nostdout():
    saved_stdout = sys.stdout
    saved_stderr = sys.stderr
    sys.stdout = StringIO()
    sys.stderr = StringIO()
    yield
    sys.stdout = saved_stdout
    sys.stderr = saved_stderr


# Save all available architectures off
available_archs = [tup[3]() for tup in archinfo.arch.arch_id_map if len(tup) >= 3]


class SupportedOptLevels(IntEnum):
    StrictUnopt = -1
    Unopt = 0
    Opt = 1
    StrictOpt = 2


def consume_random_arch(fdp: atheris.FuzzedDataProvider) -> archinfo.Arch:
    return fdp.PickValueInList(available_archs)


def TestOneInput(data: bytes):
    fdp = EnhancedFuzzedDataProvider(data)

    arch = consume_random_arch(fdp)

    try:
        with nostdout():
            data = fdp.ConsumeRandomBytes()

            irsb = pyvex.lift(
                data,
                fdp.ConsumeInt(arch.bits),
                arch,
                max_bytes=fdp.ConsumeIntInRange(0, len(data)),
                max_inst=fdp.ConsumeInt(16),
                bytes_offset=fdp.ConsumeIntInRange(0, len(data)),
                opt_level=fdp.PickValueInEnum(SupportedOptLevels)
            )
            irsb.pp()
    except pyvex.PyVEXError:
        return -1
    except OverflowError:
        return -1


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
