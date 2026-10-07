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
    from openpyxl.chart import (
        AreaChart,
        AreaChart3D,
        BarChart,
        BarChart3D,
        LineChart,
        LineChart3D,
        Reference,
        Series
    )

def TestInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    wb = Workbook()
    ws = wb.active
    cs = wb.create_chartsheet()
    
    choice = fdp.ConsumeIntInRange(1,6)
    chart = AreaChart()

    if choice == 2:
        chart = AreaChart3D()
    if choice == 3:
        chart = BarChart()
        chart.type = "bar" if fdp.ConsumeBool() else "col"
        chart.shape = 4
    if choice == 4:
        chart = BarChart3D()
        chart.type = "bar" if fdp.ConsumeBool() else "col"
        chart.shape = 4
    if choice == 5:
        chart = LineChart()
        chart.legend = None
    if choice == 6:
        chart = LineChart3D()
        chart.legend = None
    
    #Chart basic settings    
    chart.title = fdp.ConsumeString(10)
    chart.style = 13
    chart.x_axis.title = fdp.ConsumeString(10)
    chart.y_axis.title = fdp.ConsumeString(10)

    #Chart data
    ws.append(['Col1', 'Col2', 'Col3'])
    for i in range(2,8):
        ws.append([i,fdp.ConsumeIntInRange(1,100),fdp.ConsumeIntInRange(1,100)])

    chart.add_data(Reference(ws, min_col=2, min_row=1, max_col=3, max_row=7), titles_from_data=True)
    chart.set_categories(Reference(ws, min_col=1, min_row=1, max_row=7))

    #Random add chart to worksheet or chartsheet
    ws.add_chart(chart, "A10") if fdp.ConsumeBool() else cs.add_chart(chart)
    wb.save('%s.xlsx'%fdp.ConsumeString(10))

def main():
    atheris.Setup(sys.argv, TestInput, enable_python_coverage=True)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
