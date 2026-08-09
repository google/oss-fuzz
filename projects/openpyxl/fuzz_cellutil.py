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
    import openpyxl.utils.cell as cell

def TestInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    try:
        cell.absolute_coordinate(fdp.ConsumeString(20))
        cell.cols_from_range(fdp.ConsumeString(20))
        cell.column_index_from_string(fdp.ConsumeString(20))
        cell.coordinate_from_string(fdp.ConsumeString(20))
        cell.coordinate_to_tuple(fdp.ConsumeString(20))
        cell.get_column_interval(fdp.ConsumeInt(10),fdp.ConsumeInt(10))
        cell.get_column_letter(fdp.ConsumeInt(10))
        cell.quote_sheetname(fdp.ConsumeString(20))
        cell.range_boundaries(fdp.ConsumeString(20))
        cell.range_to_tuple(fdp.ConsumeString(20))
        cell.rows_from_range(fdp.ConsumeString(20))
    except ValueError as e:
       error_list = [
           "is not a valid coordinate range",
           "Invalid column index",
           "is not a valid column name",
           "is not a valid coordinate or range",
           "Value must be of the form sheetname!A1:E4"
       ]
       expected_error = False
       for error in error_list:
           if error in str(e):
               expected_error = True
       if not expected_error:
           raise e
    except CellCoordinatesException:
        pass

def main():
    atheris.Setup(sys.argv, TestInput, enable_python_coverage=True)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
