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
"""Targets pyplot. Both native and python code"""

import os
import sys
import atheris
import matplotlib.pyplot as plt
import numpy as np

def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    
    data = list()
    for i in range(16):
        data.append((fdp.ConsumeIntInRange(0,4000), fdp.ConsumeIntInRange(0,4000)))

    dim = len(data[0])
    w = 0.75
    dimw = w / dim

    fig, ax = plt.subplots()
    x = np.arange(len(data))
    for i in range(len(data[0])):
        y = [d[i] for d in data]
        b = ax.bar(x + i * dimw, y, dimw, bottom=0.001)

    ax.set_xticks(x + dimw / 2, labels=map(str, x))
    ax.set_yscale('log')
    ax.set_xlabel(fdp.ConsumeUnicodeNoSurrogates(64))
    ax.set_ylabel(fdp.ConsumeUnicodeNoSurrogates(64))
    plt.savefig("fuzz_fig.png")


def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
