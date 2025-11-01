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
"""Targets the pandas to_datetime function."""

import sys
import atheris
import pandas as pd

from pandas.errors import (
    ParserError,
    OutOfBoundsDatetime
)


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    try:
        input_str = fdp.ConsumeUnicodeNoSurrogates(100)
        errors = fdp.PickValueInList(['raise', 'coerce', 'ignore', fdp.ConsumeUnicodeNoSurrogates(20)])
        unit = fdp.PickValueInList([None, 'ns', 'us', 'ms', 's', 'D', 'M', 'Y', fdp.ConsumeUnicodeNoSurrogates(20)])
        origin = fdp.PickValueInList(['unix', 'julian', 'epoch', fdp.ConsumeUnicodeNoSurrogates(20)])
        dayfirst = fdp.ConsumeBool()
        yearfirst = fdp.ConsumeBool()
        exact = fdp.ConsumeBool()
        cache = fdp.ConsumeBool()

        pd.to_datetime(
            arg=input_str,
            errors=errors,
            unit=unit,
            origin=origin,
            dayfirst=dayfirst,
            yearfirst=yearfirst,
            exact=exact,
            cache=cache
        )

    except (
            ParserError,  # When parsing a date from string fails.
            ValueError,  # When another datetime conversion error happens.
            OutOfBoundsDatetime  # catching attempts to create a DatetimeIndex, which may raise from cast()
    ):
        pass


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.instrument_all()
    atheris.Fuzz()


if __name__ == "__main__":
    main()
