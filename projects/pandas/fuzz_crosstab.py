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
"""Targets pandas crosstab function with fuzzing data to explore edge cases."""

import atheris
import sys
import pandas as pd
import numpy as np


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    try:
        num_elements = fdp.ConsumeIntInRange(1, 100)
        a = np.array(
            [fdp.ConsumeUnicode(fdp.ConsumeIntInRange(1, 100)) for _ in range(num_elements)],
            dtype=object
        )

        b = np.array(
            [fdp.ConsumeUnicode(fdp.ConsumeIntInRange(1, 100)) for _ in range(num_elements)],
            dtype=object
        )

        pd.crosstab(
            a,
            b,
            rownames=[fdp.ConsumeUnicode(fdp.ConsumeIntInRange(1, 100))],
            colnames=[fdp.ConsumeUnicode(fdp.ConsumeIntInRange(1, 100))]
        )

    except (
            ValueError  # If there is a mismatch in dimensions or inappropriate values are provided.
    ):
        pass


def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
