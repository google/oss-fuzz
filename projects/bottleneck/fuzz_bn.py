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
"""Scalar equivalene checker"""

import os
import sys
import atheris

import numpy as np
from numpy.testing import assert_array_almost_equal
import bottleneck as bn


def gen_random_array(data, fdp = None):
  if fdp is None:
    fdp = atheris.FuzzedDataProvider(data)
  l1 = list()
  for i in range(fdp.ConsumeIntInRange(5, 3000)):
    l1.append(fdp.ConsumeIntInRange(1,10000))
  a = np.array(l1)
  return a

def TestOneInput(data):
  """Tests scalar equivalence and also move operations"""
  fdp = atheris.FuzzedDataProvider(data)
  a = gen_random_array(data, fdp)

  func_pairs = [
    (bn.nansum, bn.slow.nansum),
    (bn.nanmean, bn.slow.nanmean),
    (bn.nanstd, bn.slow.nanstd),
    (bn.nanvar, bn.slow.nanvar),
    (bn.nanmin, bn.slow.nanmin),
    (bn.median, bn.slow.median),
    (bn.nanmedian, bn.slow.nanmedian),
    (bn.ss, bn.slow.ss),
    (bn.nanargmin, bn.slow.nanargmin),
    (bn.nanargmax, bn.slow.nanargmax),
    (bn.anynan, bn.slow.anynan),
    (bn.allnan, bn.slow.allnan),
  ]

  idx = 0
  for func0, func1 in func_pairs:
    idx = idx + 1
    actual = func0(a)
    desired = func1(a)
    assert_array_almost_equal(
      actual,
      desired,
      err_msg="Failed scalar equivalence"
    )


  # Test move operations
  window = fdp.ConsumeIntInRange(2, 50)
  min_count = fdp.ConsumeIntInRange(1, window)
  try:
    actual = bn.move_median(
      a,
      window=window,
      min_count = fdp.ConsumeIntInRange(1,100)
    )
  except ValueError:
    return
  try:
    desired = bn.slow.move_median(
      a,
      window=window,
      min_count=fdp.ConsumeIntInRange(1, 100)
    )
  except ValueError:
    return
  assert_array_almost_equal(
    actual,
    desired,
    err_msg="Failed move operation"
  )


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
  atheris.Fuzz()

if __name__ == "__main__":
  main()
