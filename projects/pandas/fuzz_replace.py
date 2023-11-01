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
"""This fuzzer script targets the pandas replace function with variety of inputs and edge cases."""

import sys
import atheris
import pandas as pd

def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    try:
        num_rows = fdp.ConsumeIntInRange(3, 100)
        num_columns = fdp.ConsumeIntInRange(3, 100)
        col_names = [fdp.ConsumeString(fdp.ConsumeIntInRange(1, 100)) for _ in range(num_columns)]

        data = {}
        for col_name in col_names:
            if fdp.ConsumeBool():
                data[col_name] = [fdp.ConsumeInt(10) for _ in range(num_rows)]
            elif fdp.ConsumeBool():
                data[col_name] = [fdp.ConsumeString(100) for _ in range(num_rows)]
            elif fdp.ConsumeBool():
                data[col_name] = [fdp.ConsumeIntInRange(0, 2100) for _ in range(num_rows)]
            elif fdp.ConsumeBool():
                data[col_name] = [fdp.ConsumeFloat() for _ in range(num_rows)]
            else:
                data[col_name] = [fdp.ConsumeBool() for _ in range(num_rows)]

        df = pd.DataFrame(data)

        to_replace = fdp.ConsumeIntInRange(1, 100)
        value = fdp.ConsumeIntInRange(101, 200)
        inplace = fdp.ConsumeBool()
        limit = fdp.ConsumeIntInRange(1, num_rows - 1) if fdp.ConsumeBool() else None
        regex = fdp.ConsumeBool()
        method = fdp.PickValueInList(['pad', 'ffill', 'bfill', 'backfill', fdp.ConsumeString(20), None]) if fdp.ConsumeBool() else None

        df.replace(
            to_replace=to_replace,
            value=value,
            inplace=inplace,
            limit=limit,
            regex=regex,
            method=method
        )

    except (
        TypeError,
        ValueError,
        KeyError
    ):
        pass

def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.instrument_all()
    atheris.Fuzz()

if __name__ == "__main__":
    main()
