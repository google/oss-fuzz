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

"""This fuzzer script targets the pandas melt and map functions, creating a variety of DataFrames with mixed data
types and then transforming them using melting and mapping operations."""

import sys
import atheris
import pandas as pd


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    try:
        groups = {
            fdp.ConsumeString(10): fdp.ConsumeUnicodeNoSurrogates(10),
            fdp.ConsumeString(10): fdp.ConsumeUnicodeNoSurrogates(10)
        }

        num_rows = fdp.ConsumeIntInRange(3, 30)
        num_columns = fdp.ConsumeIntInRange(3, 30)
        col_names = [fdp.ConsumeString(fdp.ConsumeIntInRange(1, 15)) for _ in range(num_columns)]

        df_content = {}
        for col_name in col_names:
            if fdp.ConsumeBool():
                df_content[col_name] = [fdp.ConsumeInt(10) for _ in range(num_rows)]
            elif fdp.ConsumeBool():
                df_content[col_name] = [fdp.ConsumeString(10) for _ in range(num_rows)]
            elif fdp.ConsumeBool():
                df_content[col_name] = [fdp.ConsumeIntInRange(0, 2100) for _ in range(num_rows)]
            elif fdp.ConsumeBool():
                df_content[col_name] = [fdp.ConsumeFloat() for _ in range(num_rows)]
            else:
                df_content[col_name] = [fdp.ConsumeBool() for _ in range(num_rows)]

        id_vars_data = [
            col_names[fdp.ConsumeIntInRange(0, len(col_names) - 1)],
            col_names[fdp.ConsumeIntInRange(0, len(col_names) - 1)],
            col_names[fdp.ConsumeIntInRange(0, len(col_names) - 1)]
        ]
        if fdp.ConsumeBool():
            id_vars_data.append(fdp.ConsumeString(fdp.ConsumeIntInRange(1, 15)))

        df = pd.DataFrame(df_content)
        name = fdp.ConsumeString(20)
        df = pd.melt(
            df,
            id_vars=id_vars_data,
            value_vars=[
                col_names[fdp.ConsumeIntInRange(0, len(col_names) - 1)],
                col_names[fdp.ConsumeIntInRange(0, len(col_names) - 1)]
            ],
            var_name='gf', value_name=fdp.ConsumeString(10)
        )

        local_var_name = 'gf' if fdp.ConsumeBool() else fdp.ConsumeString(10)
        df[name] = df[local_var_name].map(groups)
    except (
            KeyError,  # if `id_vars` are not in the frame.
            ValueError # if initial data from seed is empty and fdp produces empty data.
    ):
        pass


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.instrument_all()
    atheris.Fuzz()


if __name__ == "__main__":
    main()
