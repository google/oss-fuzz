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
import datetime
with atheris.instrument_imports():
    from openpyxl import Workbook

def TestInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    wb = Workbook()
    ws = wb.active
    
    #Row/Col management
    ws.insert_rows(fdp.ConsumeInt(100))
    ws.insert_cols(fdp.ConsumeInt(100))
    ws.delete_rows(fdp.ConsumeInt(100),fdp.ConsumeInt(100))
    ws.delete_cols(fdp.ConsumeInt(100),fdp.ConsumeInt(100))
    ws.column_dimensions.group(
        chr(fdp.ConsumeIntInRange(65,90)),
        chr(fdp.ConsumeIntInRange(65,90)),
        hidden=True
    )
    ws.row_dimensions.group(
        fdp.ConsumeInt(100),
        fdp.ConsumeInt(100),
        hidden=True
    )
   
    #Cell management
    ws['A1'] = datetime.datetime(2022, 1, 1)
    format = ws['A1'].number_format

    ws.move_range(
        "G4:H10", 
        rows=fdp.ConsumeInt(100), 
        cols=fdp.ConsumeInt(100), 
        translate=fdp.ConsumeBool()
    )

    try:
        sr = fdp.ConsumeInt(100)
        sc = fdp.ConsumeInt(100)
        er = fdp.ConsumeInt(100)
        ec = fdp.ConsumeInt(100)
        ws.merge_cells(start_row=sr, start_column=sc, end_row=er, end_column=ec)
        ws.unmerge_cells(start_row=sr, start_column=sc, end_row=er, end_column=ec) 
    except ValueError as e:
        if "Min value is 1" not in str(e):
           raise e
    

    wb.save('%s.xlsx'%fdp.ConsumeString(10))

def main():
    atheris.Setup(sys.argv, TestInput, enable_python_coverage=True)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
