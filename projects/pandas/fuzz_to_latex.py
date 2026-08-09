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
"""Targets the to_latex function."""

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
        columns = None if fdp.ConsumeBool() else list(df.columns)
        header = fdp.ConsumeBool()
        index = fdp.ConsumeBool()
        na_rep = fdp.ConsumeUnicodeNoSurrogates(5)
        float_format = "fixed" if fdp.ConsumeBool() else None
        sparsify = fdp.ConsumeBool()
        index_names = fdp.ConsumeBool()
        bold_rows = fdp.ConsumeBool()
        columns_format = None if fdp.ConsumeBool() else fdp.ConsumeUnicodeNoSurrogates(5)
        longtable = fdp.ConsumeBool()

        df.to_latex(
            columns=columns,
            header=header,
            index=index,
            na_rep=na_rep,
            formatters=None,
            float_format=float_format,
            sparsify=sparsify,
            index_names=index_names,
            bold_rows=bold_rows,
            column_format=columns_format,
            longtable=longtable
        )



    except(
            ValueError,  # If column_format is not a valid string
            ImportError # If Jinja2 is imported for latex
    ):
        pass


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.instrument_all()
    atheris.Fuzz()


if __name__ == "__main__":
    main()
