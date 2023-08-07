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
import atheris

with atheris.instrument_imports(include=["pyvex"]):
    import pyvex

# Additional imports
import archinfo
from contextlib import contextmanager
from io import StringIO


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


def consume_random_bytes(fdp: atheris.FuzzedDataProvider) -> bytes:
    """
    Returns a fuzz-guided "random" number of bytes
    :param fdp: FuzzedDataProvider to generate bytes with
    :return: A sequence of bytes
    """
    count = fdp.ConsumeIntInRange(0, fdp.remaining_bytes())
    return fdp.ConsumeBytes(count)


def consume_random_address(fdp: atheris.FuzzedDataProvider) -> bytes:
    """
    Generates a meaningful memory address to mark the beginning of the IRSB being lifted
    :param fdp: FuzzedDataProvider to generate address with
    :return: A random address
    """
    return fdp.ConsumeInt(4)


def consume_random_arch(fdp: atheris.FuzzedDataProvider) -> archinfo.Arch:
    return fdp.PickValueInList(available_archs)


def TestOneInput(data: bytes):
    fdp = atheris.FuzzedDataProvider(data)

    try:
        with nostdout():
            irsb = pyvex.lift(
                consume_random_bytes(fdp),
                consume_random_address(fdp),
                consume_random_arch(fdp))
            irsb.pp()
    except pyvex.PyVEXError:
        return -1


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
