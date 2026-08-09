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
"""Targets sklearn.preprocessing"""
import os
import sys
import atheris

import numpy as np
from sklearn.preprocessing import OneHotEncoder
from sklearn.preprocessing import OrdinalEncoder

def get_random_arr(fdp):
    l1 = list()
    for i in range(fdp.ConsumeIntInRange(1, 1000)):
        l1.append(
            [
                fdp.ConsumeIntInRange(1, 1000),
                fdp.ConsumeIntInRange(1, 1000),
                fdp.ConsumeIntInRange(1, 1000)
            ]
        )
    return l1


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    oh_x1 = np.array(get_random_arr(fdp))
    oh_x2 = np.array(get_random_arr(fdp))

    # Test that one hot encoder raises error for unknown features
    # present during transform.
    oh = OneHotEncoder(handle_unknown="error")
    oh.fit(oh_x1)
    try:
        oh.transform(oh_x2)
    except ValueError:
        pass

    
    oe_x1 = np.array(get_random_arr(fdp))
    oe_x2 = np.array(get_random_arr(fdp))

    oe = OrdinalEncoder(handle_unknown="use_encoded_value", unknown_value=-1)
    oe.fit(oe_x1)
    try:
        oe.transform(oe_x2)
    except ValueError:
        pass


def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
