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
import json
import atheris
import tabulate


def ConsumeListofLists(fdp):
    list = []
    num_lists = fdp.ConsumeIntInRange(1, 100)
    for _ in range(num_lists):
        list.append(fdp.ConsumeFloatListInRange(num_lists, 1, 1000))
    return list


def ConsumeDictionary(fdp):
    dictionary = {}
    dict_size = fdp.ConsumeIntInRange(1, 100)
    for _ in range(dict_size):
        dictionary[fdp.ConsumeUnicodeNoSurrogates(
            fdp.ConsumeIntInRange(0, 100))] = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 100))
    return dictionary


def ConsumeNestedDictionary(fdp):
    dictionary = {}
    dict_size = fdp.ConsumeIntInRange(1, 100)
    for _ in range(dict_size):
        t_or_f = fdp.ConsumeBool()
        if t_or_f is True:
            dictionary[fdp.ConsumeUnicodeNoSurrogates(
                fdp.ConsumeIntInRange(0, 100))] = ConsumeDictionary(fdp)
        else:
            dictionary[fdp.ConsumeUnicodeNoSurrogates(
                fdp.ConsumeIntInRange(0, 100))] = fdp.ConsumeUnicodeNoSurrogates(
                fdp.ConsumeIntInRange(0, 100))
    return dictionary


def ConsumeDictionaryWithList(fdp):
    dictionary = {}
    dict_size = fdp.ConsumeIntInRange(1, 100)
    for _ in range(dict_size):
        dictionary[fdp.ConsumeUnicodeNoSurrogates(
            fdp.ConsumeIntInRange(1, 100))] = fdp.ConsumeIntListInRange(
            fdp.ConsumeIntInRange(1, 100), 1, 100)
    return dictionary


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    table_format = fdp.PickValueInList(tabulate.tabulate_formats)
    col_align_num = fdp.PickValueInList(
        ["right", "center", "left", "decimal", None])
    col_align_str = fdp.PickValueInList(
        ["right", "center", "left", None])

    # Create random dictionary
    try:
        fuzzed_dict = json.loads(
            fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 100)))
    except:
        return
    if type(fuzzed_dict) is not dict:
        return

    # Test tabulate with various inputs
    t1 = tabulate.tabulate(
        fuzzed_dict,
        tablefmt=table_format
    )
    t2 = tabulate.tabulate(
        ConsumeDictionary(fdp),
        tablefmt=table_format,
        headers="keys"
    )
    t3 = tabulate.tabulate(
        ConsumeListofLists(fdp),
        tablefmt=table_format,
        headers="firstrow"
    )
    t4 = tabulate.tabulate(
        ConsumeNestedDictionary(fdp),
        tablefmt=table_format
    )
    t5 = tabulate.tabulate(
        ConsumeDictionaryWithList(fdp),
        tablefmt=table_format
    )
    almost_all_args = tabulate.tabulate(
        ConsumeListofLists(fdp),
        tablefmt=table_format,
        headers="firstrow",
        showindex="always",
        numalign=col_align_num,
        stralign=col_align_str,
        floatfmt=".4f"
    )

    # make and implement custom table formator
    custom_separator = tabulate.simple_separated_format(
        fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(1, 100)))
    tabulate.tabulate(ConsumeDictionary(fdp), tablefmt=custom_separator)


def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
