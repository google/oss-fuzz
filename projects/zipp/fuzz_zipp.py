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

import zipp
import zipfile
import io


def gen_path(fdp):
    """Generate a string with maximum 4 instances of /"""
    s1 = fdp.ConsumeUnicodeNoSurrogates(15)
    while s1.count("/") > 4:
        # Replace the first occurrence of /
        s1 = s1.replace("/", "a", 1)
    return s1


def build_fixture(fdp):
    """Generate a random zip structure"""
    data = io.BytesIO()
    zf = zipfile.ZipFile(data, "w")
    number_of_entries = fdp.ConsumeIntInRange(2, 10)
    for i in range(number_of_entries):
        zf.writestr(gen_path(fdp), fdp.ConsumeBytes(20))
    zf.filename = "fuzzGen.zip"
    return zf


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    try:
        zf = build_fixture(fdp)
    except:
        # On any issue we return
        return

    root = zipp.Path(zf)
    for elem in root.iterdir():
        # perform simple operations on the elem
        elem.is_dir()
        elem.is_file()


def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
