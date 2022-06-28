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
    import openpyxl

def TestInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    wb = openpyxl.Workbook()
    ws = wb.active

    ws['A%d'%fdp.ConsumeIntInRange(1,sys.maxsize)] = fdp.ConsumeInt(10)
    ws.append(fdp.ConsumeIntList(3,5))

    ws['B%d'%fdp.ConsumeIntInRange(1,sys.maxsize)] = fdp.ConsumeUnicode(10)
    ws['C%d'%fdp.ConsumeIntInRange(1,sys.maxsize)] = fdp.ConsumeBytes(10)
    ws['D%d'%fdp.ConsumeIntInRange(1,sys.maxsize)] = fdp.ConsumeString(10)
    ws['E%d'%fdp.ConsumeIntInRange(1,sys.maxsize)] = fdp.ConsumeFloat()
    ws['F%d'%fdp.ConsumeIntInRange(1,sys.maxsize)] = fdp.ConsumeBool()

    wb.save('%s.xlsx'%fdp.ConsumeString(10))

def main():
    atheris.Setup(sys.argv, TestInput, enable_python_coverage=True)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
