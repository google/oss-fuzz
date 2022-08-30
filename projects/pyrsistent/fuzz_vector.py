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

from pyrsistent._pvector import python_pvector


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    
    p = python_pvector([])
    e = None

    # Perform a sequence of arbitrary operations on the vector.
    ops_num = fdp.ConsumeIntInRange(5, 500)
    for i in range(ops_num):
        op = fdp.ConsumeIntInRange(1, 6)
        if op == 1:
            p = p.append(fdp.ConsumeIntInRange(1,2000))
        elif op == 2:
            p.count(fdp.ConsumeIntInRange(1, 200))
        elif op == 3:
            try:
                p = p.set(fdp.ConsumeIntInRange(1, 100), fdp.ConsumeIntInRange(1, 100))
            except IndexError:
                pass
        elif op == 4:
            try:
                p = p.remove(fdp.ConsumeIntInRange(1,20))
            except ValueError as exc:
                if "not in list" not in str(exc):
                    raise exc
        elif op == 5:
            e = p.evolver()
        elif op == 6 and e != None:
            _ = len(e)


def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
