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
"""Calls the APIs of more_itertools with random settings"""
import sys
import atheris
import more_itertools


def get_random_list(fdp, min_len=5, max_len=100):
  return fdp.ConsumeIntList(fdp.ConsumeIntInRange(min_len, max_len), 4)


def check_sliced(fdp):
  seq2 = [x for x in fdp.ConsumeUnicodeNoSurrogates(1024)]
  try:
    l1 = list(more_itertools.sliced(seq2, 3, strict=fdp.ConsumeBool()))
  except ValueError:
    pass


def check_windowed(fdp):
  idxs = get_random_list(fdp)
  try:
    l2 = list(more_itertools.windowed(idxs, fdp.ConsumeIntInRange(1, 100)))
    l2 = list(more_itertools.windowed(idxs, fdp.ConsumeIntInRange(-10, 100)))
  except ValueError:
    pass


def check_distinct_combinations(fdp):
  idxs = get_random_list(fdp)
  try:
    l3 = list(more_itertools.distinct_combinations(
        idxs, fdp.ConsumeIntInRange(5, 10)))
    l3 = list(more_itertools.distinct_combinations(
        idxs, fdp.ConsumeIntInRange(-10, 10)))
  except ValueError:
    pass


def check_substrings(fdp):
  c3 = [''.join(s) for s in more_itertools.substrings(fdp.ConsumeUnicodeNoSurrogates(24))]


def check_substrings_indexes(fdp):
  l1 = get_random_list(fdp)
  try:
    list(more_itertools.substrings_indexes(l1))
  except ValueError:
    pass


def check_locate(fdp):
  l1 = get_random_list(fdp)
  try:
    list(more_itertools.locate(l1))
  except ValueError:
    pass


def check_islice_extended(fdp):
  l1 = get_random_list(fdp)
  try:
    list(more_itertools.islice_extended(l1, 3, 10))
  except ValueError:
    pass


def check_interleave_evenly(fdp):
  l1 = get_random_list(fdp)
  l2 = get_random_list(fdp)
  try:
    list(more_itertools.interleave_evenly([l1, l2]))
  except ValueError:
    pass


def check_collapse(fdp):
  l1 = get_random_list(fdp)
  try:
    list(more_itertools.collapse(l1))
  except ValueError:
    pass
  

def check_chunked(fdp):
  l1 = get_random_list(fdp)
  try:
    list(more_itertools.chunked(l1, n=fdp.ConsumeIntInRange(-10, 100)))
  except ValueError:
    pass


def check_intersperse(fdp):
  l1 = get_random_list(fdp)
  try:
    list(more_itertools.intersperse('a', l1))
  except ValueError:
    pass
  

def TestOneInput(data):
  fdp = atheris.FuzzedDataProvider(data)
  targets = [
    check_sliced,
    check_windowed,
    check_distinct_combinations,
    check_substrings,
    check_interleave_evenly,
    check_chunked,
    check_intersperse,
    check_substrings_indexes,
    check_locate,
    check_islice_extended,
  ]

  target = fdp.PickValueInList(targets)
  target(fdp)


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
