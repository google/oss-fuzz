#!/usr/bin/python3
# Copyright 2023 Google LLC
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
import sys
import atheris

import nvd3


def TestOneInput(data):
  fdp = atheris.FuzzedDataProvider(data)

  # Chart with two series
  chart = nvd3.lineChart(name=fdp.ConsumeUnicodeNoSurrogates(24),
                         x_is_date=fdp.ConsumeBool(),
                         x_axis_format=fdp.ConsumeUnicodeNoSurrogates(12))
  xdata = list(range(0, 256))
  ydata = fdp.ConsumeIntList(256, 4)
  ydata2 = fdp.ConsumeIntList(256, 4)

  # Create random args for each serie
  kwargs1 = dict()
  for i in range(fdp.ConsumeIntInRange(5, 10)):
    kwargs1[fdp.ConsumeUnicodeNoSurrogates(
        24)] = fdp.ConsumeUnicodeNoSurrogates(24)

  kwargs2 = dict()
  for i in range(fdp.ConsumeIntInRange(5, 10)):
    kwargs2[fdp.ConsumeUnicodeNoSurrogates(
        24)] = fdp.ConsumeUnicodeNoSurrogates(24)

  # Add thw two series
  extra_serie = {
      fdp.ConsumeUnicodeNoSurrogates(24): {
          fdp.ConsumeUnicodeNoSurrogates(24):
              fdp.ConsumeUnicodeNoSurrogates(24),
          fdp.ConsumeUnicodeNoSurrogates(24):
              fdp.ConsumeUnicodeNoSurrogates(24)
      }
  }
  chart.add_serie(y=ydata,
                  x=xdata,
                  name=fdp.ConsumeUnicodeNoSurrogates(24),
                  extra=extra_serie,
                  **kwargs1)
  extra_serie = {
      fdp.ConsumeUnicodeNoSurrogates(24): {
          fdp.ConsumeUnicodeNoSurrogates(24):
              fdp.ConsumeUnicodeNoSurrogates(24),
          fdp.ConsumeUnicodeNoSurrogates(24):
              fdp.ConsumeUnicodeNoSurrogates(24)
      }
  }
  chart.add_serie(y=ydata2,
                  x=xdata,
                  name=fdp.ConsumeUnicodeNoSurrogates(24),
                  extra=extra_serie,
                  **kwargs2)

  # Construct the HTML
  chart.buildhtml()


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
