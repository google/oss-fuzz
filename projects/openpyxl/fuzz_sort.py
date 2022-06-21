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

def TestInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    wb = Workbook()
    ws = wb.active
    
    ws.append(['Col1', 'Col2'])
    for i in range(2,20):
        ws.append([fdp.ConsumeIntInRange(1,100),fdp.ConsumeIntInRange(1,100)])

    ws.auto_filter.ref = "A%d:B%d"%(fdp.ConsumeInt(10),fdp.ConsumeInt(10))
    ws.auto_filter.add_filter_column(0, [fdp.ConsumeInt(10),fdp.ConsumeInt(10)])
    ws.auto_filter.add_sort_condition("B%d:B%d"%(fdp.ConsumeInt(10),fdp.ConsumeInt(10)))

    wb.save('%s.xlsx'%fdp.ConsumeString(10))

def main():
    atheris.Setup(sys.argv, TestInput, enable_python_coverage=True)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
