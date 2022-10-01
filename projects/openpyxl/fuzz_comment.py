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

import atheris
import sys
with atheris.instrument_imports():
    from openpyxl import Workbook
    from openpyxl.comments import Comment

def TestInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    wb = Workbook()
    ws = wb.active

    #Set Comment
    c1 = ws['A1'].comment
    c1 = Comment(fdp.ConsumeUnicodeNoSurrogates(10),
        fdp.ConsumeUnicodeNoSurrogates(10))
    c1.width = 300
    c1.height = 50
    ws['A1'].comment = c1

    #Double assign comment
    c2 = Comment(fdp.ConsumeUnicodeNoSurrogates(10),
        fdp.ConsumeUnicodeNoSurrogates(10))
    ws['B1'].comment = c2
    ws['C1'].comment = c2

    try:
        wb.save('%s.xlsx'%fdp.ConsumeUnicodeNoSurrogates(10))
    except ValueError as e:
        if "embedded null byte" not in str(e):
            raise e
    except FileNotFoundError:
       # Expected for corrupted file name
       pass

def main():
    atheris.Setup(sys.argv, TestInput, enable_python_coverage=True)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
