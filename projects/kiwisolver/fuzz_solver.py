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
import atheris

from kiwisolver import (
    Solver,
    UnsatisfiableConstraint,
    Variable,
)


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    s = Solver()

    # Create an arbitrary set of variables
    variables = []
    num_of_variables = fdp.ConsumeIntInRange(2, 10)
    for v in range(num_of_variables):
        variables.append(Variable(fdp.ConsumeUnicodeNoSurrogates(20)))
        s.addEditVariable(variables[-1], "weak")

    # Apply a random set of constraints on these variables
    num_of_ops = fdp.ConsumeIntInRange(2, 10)
    for i in range(num_of_ops):
        op = fdp.ConsumeIntInRange(1,3)
        var = variables[fdp.ConsumeIntInRange(0,len(variables)-1)]
        c = 1 * var
        for i2 in range(fdp.ConsumeIntInRange(2, 5)):
            if op == 1:
                c = c + fdp.ConsumeIntInRange(1, 100)
            elif op == 2:
                c = c - fdp.ConsumeIntInRange(1, 100)
            elif op == 3:
                c = c * fdp.ConsumeIntInRange(1, 100)

        # Add constraint
        constr = fdp.ConsumeIntInRange(0,2)
        if constr == 0:
            c = c >= 0
        elif constr == 1:
            c = c <= 0
        else:
            c = c == 0

        try:
            s.addConstraint(c)
        except UnsatisfiableConstraint:
            return

    # Set a condition/update variables.
    s.updateVariables()

def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
