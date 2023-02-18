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
import toolz
from operator import add


def TestOneInput(data):
  fdp = atheris.FuzzedDataProvider(data)
  val_1 = fdp.ConsumeUnicodeNoSurrogates(24)

  fuzz_int_list_1 = fdp.ConsumeIntList(fdp.ConsumeIntInRange(1, 100), 4)
  fuzz_int_list_2 = fdp.ConsumeIntList(fdp.ConsumeIntInRange(1, 100), 4)
  fuzz_int_list_3 = fdp.ConsumeIntList(fdp.ConsumeIntInRange(1, 100), 4)

  fuzz_int_list_4 = []
  fuzz_int_list_5 = []
  for i in range(fdp.ConsumeIntInRange(10, 50)):
    fuzz_int_list_4.append((i, fdp.ConsumeUnicodeNoSurrogates(12)))
    fuzz_int_list_5.append((i, fdp.ConsumeUnicodeNoSurrogates(12)))

  str_list3 = []
  str_list4 = []
  for i in range(fdp.ConsumeIntInRange(10, 50)):
    str_list3.append((fdp.ConsumeUnicodeNoSurrogates(12),
                      fdp.ConsumeUnicodeNoSurrogates(12)))
    str_list4.append((fdp.ConsumeUnicodeNoSurrogates(12),
                      fdp.ConsumeUnicodeNoSurrogates(12)))

  list(
      toolz.itertoolz.merge_sorted(fuzz_int_list_1, fuzz_int_list_2,
                                   fuzz_int_list_3))
  list(
      toolz.itertoolz.merge_sorted(fuzz_int_list_1,
                                   fuzz_int_list_2,
                                   fuzz_int_list_3,
                                   key=lambda x: x + 2))
  list(
      toolz.itertoolz.join(toolz.itertoolz.first, fuzz_int_list_4,
                           toolz.itertoolz.second, fuzz_int_list_5))

  list(
      toolz.itertoolz.join(toolz.itertoolz.second, str_list3,
                           toolz.itertoolz.first, str_list4))
  list(
      toolz.itertoolz.join(toolz.itertoolz.second,
                           str_list3,
                           toolz.itertoolz.first,
                           str_list4,
                           left_default=None,
                           right_default=None))
  list(
      toolz.itertoolz.join(lambda x: x,
                           str_list3,
                           lambda x: x,
                           str_list4,
                           left_default=None))
  list(
      toolz.itertoolz.join(lambda x: x,
                           str_list3,
                           lambda x: x,
                           str_list4,
                           right_default=None))
  list(toolz.itertoolz.join(lambda x: x, str_list3, lambda x: x, str_list4))
  list(toolz.itertoolz.diff(fuzz_int_list_2, fuzz_int_list_3))
  list(toolz.itertoolz.partition_all(3, fuzz_int_list_3))

  try:
    toolz.itertoolz.get(fdp.ConsumeIntInRange(1, 1000000), fuzz_int_list_3)
    toolz.itertoolz.get([1, 2], fuzz_int_list_3)
  except (KeyError, IndexError, TypeError):
    pass

  toolz.itertoolz.isdistinct(fuzz_int_list_3)
  toolz.itertoolz.isdistinct(fdp.ConsumeUnicodeNoSurrogates(256))
  toolz.itertoolz.isiterable(fuzz_int_list_3)
  toolz.itertoolz.peekn(fdp.ConsumeIntInRange(1, 10), fuzz_int_list_3)
  toolz.itertoolz.peek(fuzz_int_list_3)
  list(toolz.itertoolz.tail(fdp.ConsumeIntInRange(1, 1000), fuzz_int_list_2))
  tuple(toolz.itertoolz.unique(fuzz_int_list_3))
  tuple(toolz.itertoolz.unique(fuzz_int_list_3, key=lambda x: x + 3))
  list(
      toolz.itertoolz.interleave(
          [fuzz_int_list_1, fuzz_int_list_2, fuzz_int_list_3]))
  list(toolz.itertoolz.accumulate(add, fuzz_int_list_3))

  toolz.itertoolz.reduceby(lambda x: x + 8 == 2, add, fuzz_int_list_2)


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
