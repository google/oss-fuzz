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
import json
import atheris
import tabulate


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    tabulate_formats = list(tabulate._table_formats.keys())
    table_format = tabulate_formats[fdp.ConsumeIntInRange(0, len(tabulate_formats)-1)]


    # Create random dictionary
    try:
        fuzzed_dict = json.loads(fdp.ConsumeString(sys.maxsize))
    except json.JSONDecodeError:
        return
    if type(fuzzed_dict) is not dict:
        return
    
    t1 = tabulate.tabulate(
        fuzzed_dict,
        tablefmt=table_format
    )
    return


def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
