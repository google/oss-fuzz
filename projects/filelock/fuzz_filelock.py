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
import filelock

from filelock import BaseFileLock, FileLock, SoftFileLock, Timeout, UnixFileLock

def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    filepath = os.path.join("/tmp/tmp1.txt")
    with open(filepath, "w") as f:
        f.write("random")

    lock = filelock.FileLock(filepath)
    for i in range(fdp.ConsumeIntInRange(10, 100)):
        try:
            lock.acquire()
        except IsADirectoryError:
            pass
    assert lock.is_locked
    lock.release(force=True)
    assert not lock.is_locked
    

def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
