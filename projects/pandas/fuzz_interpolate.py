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
"""Fuzzes the pandas interpolate function, generating and manipulating DataFrames with various data types to uncover
potential edge cases."""

import sys
import atheris
import pandas as pd


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    try:
        rows = fdp.ConsumeIntInRange(1, 15)
        num_rows = fdp.ConsumeIntInRange(3, 20)
        num_columns = fdp.ConsumeIntInRange(3, 20)
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

        df = pd.DataFrame(df_content)

        # Fuzz interpolate options
        method = fdp.PickValueInList(
            ['linear', 'time', 'index', 'values', 'nearest', 'zero', 'slinear', 'quadratic',
             'cubic', 'barycentric', 'krogh', 'polynomial', 'spline', 'bessel', 'holistic', 'akima',
             fdp.ConsumeString(15)])
        axis = fdp.PickValueInList([0, 1, 'index', 'columns'])
        limit = fdp.ConsumeIntInRange(1, rows) if fdp.ConsumeBool() else None
        inplace = fdp.ConsumeBool()
        limit_direction = fdp.PickValueInList(['forward', 'backward', 'both', None])
        limit_area = fdp.PickValueInList([None, 'inside', 'outside'])
        order = fdp.ConsumeIntInRange(1, 5) if method == 'polynomial' else None
        s = fdp.ConsumeFloatInRange(0, 1) if method == 'spline' else None
        robust = fdp.ConsumeBool()

        df.interpolate(
            method=method,
            axis=axis,
            limit=limit,
            inplace=inplace,
            limit_direction=limit_direction,
            limit_area=limit_area,
            order=order,
            s=s,
            robust=robust
        )

    except (
            ValueError  # If method argument is invalid
    ):
        pass


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.instrument_all()
    atheris.Fuzz()


if __name__ == "__main__":
    main()
