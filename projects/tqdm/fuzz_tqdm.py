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
"""Targets tqdm using fuzzer-derived options and data"""
import sys
import atheris

from tqdm import tqdm

def gen_random_list(fdp):
    elem_list = list()
    elem_count = fdp.ConsumeIntInRange(1, 10000)
    for i in range(elem_count):
        op = fdp.ConsumeIntInRange(1,1)
        if op == 1:
            elem_list.append(fdp.ConsumeIntInRange(10, 1000))
        if op == 2:
            elem_list.append(fdp.ConsumeUnicode(10))
        if op == 3:
            elem_list.append(fdp.ConsumeUnicodeNoSurrogates(10))
    return elem_list


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    fuzz_leave = fdp.ConsumeBool()
    fuzz_mininterval = fdp.ConsumeIntInRange(0, 20)
    fuzz_ncols = fdp.ConsumeIntInRange(0, 5)
    fuzz_unit_scale = fdp.ConsumeBool()
    fuzz_disable = fdp.ConsumeBool()

    elem_list = gen_random_list(fdp)
    dev_null = open("/dev/null", "w")
    for i in tqdm(elem_list,
                  file=dev_null,
                  leave=fuzz_leave,
                  mininterval=fuzz_mininterval,
                  ncols = fuzz_ncols,
                  unit_scale = fuzz_unit_scale,
                  disable = fuzz_disable
    ):
        pass
    dev_null.close()
    return 

def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
