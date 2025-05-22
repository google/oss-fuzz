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
from io import BytesIO

try:
    import lxml
except ImportError:
    raise ImportError("lxml is required to run the tests.")

from et_xmlfile import xmlfile

def recursive_write(xf, fdp, level):
    if level == 1:
        xf.write(fdp.ConsumeUnicodeNoSurrogates(50))
    else:
        with xf.element(fdp.ConsumeUnicodeNoSurrogates(50)):
            recursive_write(xf, fdp, level-1)


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    f2 = BytesIO()
    # Call write on et_xmlfile 10 times.
    with xmlfile(f2) as xf:
        recursive_write(xf, fdp, 10)


def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
