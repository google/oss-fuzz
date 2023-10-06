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
from toolz import dicttoolz, functoolz, itertoolz
from operator import add


def fuzz_curry(x, y):
  return x + y


def ConsumeDictionary(fdp, dict_size):
  dictionary = {}
  for _ in range(dict_size):
    dictionary[fdp.ConsumeUnicodeNoSurrogates(20)] = fdp.ConsumeIntInRange(1, 100)
  return dictionary


def ConsumeDictionaryReversed(fdp, dict_size):
  dictionary = {}
  for _ in range(dict_size):
    dictionary[fdp.ConsumeIntInRange(1, 100)] = fdp.ConsumeUnicodeNoSurrogates(20)
  return dictionary


def ConsumeDictionaryWithList(fdp, dict_size):
  dictionary = {}
  for _ in range(dict_size):
    dictionary[fdp.ConsumeUnicodeNoSurrogates(20)] = fdp.ConsumeIntListInRange(4, 1, 100)
  return dictionary


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
      toolz.merge_sorted(fuzz_int_list_1, fuzz_int_list_2,
                         fuzz_int_list_3))
  list(
      toolz.merge_sorted(fuzz_int_list_1,
                         fuzz_int_list_2,
                         fuzz_int_list_3,
                         key=lambda x: x + 2))
  list(
      toolz.join(toolz.first, fuzz_int_list_4,
                 toolz.second, fuzz_int_list_5))

  list(
      toolz.join(toolz.second, str_list3,
                 toolz.first, str_list4))
  list(
      toolz.join(toolz.second,
                 str_list3,
                 toolz.first,
                 str_list4,
                 left_default=None,
                 right_default=None))
  list(
      toolz.join(lambda x: x,
                 str_list3,
                 lambda x: x,
                 str_list4,
                 left_default=None))
  list(
      toolz.join(lambda x: x,
                 str_list3,
                 lambda x: x,
                 str_list4,
                 right_default=None))
  list(toolz.join(lambda x: x, str_list3, lambda x: x, str_list4))
  list(toolz.diff(fuzz_int_list_2, fuzz_int_list_3))
  list(toolz.partition_all(3, fuzz_int_list_3))

  try:
    toolz.get(fdp.ConsumeIntInRange(1, 1000000), fuzz_int_list_3)
    toolz.get([1, 2], fuzz_int_list_3)
  except (KeyError, IndexError, TypeError):
    pass

  toolz.isdistinct(fuzz_int_list_3)
  toolz.isdistinct(fdp.ConsumeUnicodeNoSurrogates(256))
  toolz.isiterable(fuzz_int_list_3)
  toolz.peekn(fdp.ConsumeIntInRange(1, 10), fuzz_int_list_3)
  toolz.peek(fuzz_int_list_3)
  list(toolz.tail(fdp.ConsumeIntInRange(1, 1000), fuzz_int_list_2))
  tuple(toolz.unique(fuzz_int_list_3))
  tuple(toolz.unique(fuzz_int_list_3, key=lambda x: x + 3))
  list(
      toolz.interleave(
          [fuzz_int_list_1, fuzz_int_list_2, fuzz_int_list_3]))
  list(toolz.accumulate(add, fuzz_int_list_3))

  toolz.reduceby(lambda x: x + 8 == 2, add, fuzz_int_list_2)

  # fuzz functoolz
  fuzz_curry_int = toolz.curry(fuzz_curry)
  first_number = fuzz_curry_int(fdp.ConsumeIntInRange(0, 1000))
  first_number(fdp.ConsumeIntInRange(0, 1000))

  toolz.flip(fuzz_curry, fdp.ConsumeIntInRange(0, 1000),
                      fdp.ConsumeIntInRange(0, 1000))

  # functions to use
  double = lambda i: 2 * i
  inc = lambda i: i + 1

  toolz.pipe(fdp.ConsumeIntInRange(1, 100), double, str)
  toolz.compose(inc, double)(fdp.ConsumeIntInRange(1, 100))
  toolz.compose_left(inc, double)(fdp.ConsumeIntInRange(1, 100))

  # fuzz dicttoolz
  toolz.dissoc(ConsumeDictionary(fdp, fdp.ConsumeIntInRange(1, 100)),
                                 fdp.ConsumeUnicodeNoSurrogates(
                                 fdp.ConsumeIntInRange(0, 1000)))
  toolz.assoc(ConsumeDictionary(fdp, fdp.ConsumeIntInRange(1, 100)),
                                fdp.ConsumeUnicodeNoSurrogates(
                                fdp.ConsumeIntInRange(0, 1000)),
                                fdp.ConsumeIntInRange(0, 1000))
  toolz.merge(ConsumeDictionary(fdp, fdp.ConsumeIntInRange(1, 100)),
              ConsumeDictionary(fdp, fdp.ConsumeIntInRange(1, 100)))
  toolz.merge_with(sum, ConsumeDictionary(fdp, fdp.ConsumeIntInRange(1, 100)),
                        ConsumeDictionary(fdp, fdp.ConsumeIntInRange(1, 100)))
  toolz.valmap(sum,
               ConsumeDictionaryWithList(fdp, fdp.ConsumeIntInRange(1, 100)))
  toolz.keymap(str.lower,
               ConsumeDictionaryWithList(fdp, fdp.ConsumeIntInRange(1, 100)))
  toolz.itemmap(reversed,
                ConsumeDictionary(fdp, fdp.ConsumeIntInRange(1, 100)))
  toolz.valfilter(lambda x: x + 8 == 2,
                  ConsumeDictionary(fdp, fdp.ConsumeIntInRange(1, 100)))
  toolz.keyfilter(lambda x: x + 8 == 2,
                  ConsumeDictionaryReversed(fdp, fdp.ConsumeIntInRange(1, 100)))

  # fuzz sandbox
  toolz.sandbox.core.unzip(ConsumeDictionary(fdp,
                                             fdp.ConsumeIntInRange(1, 100)))
  toolz.sandbox.core.EqualityHashKey(fdp.ConsumeUnicodeNoSurrogates(
                                     fdp.ConsumeIntInRange(0, 1000)),
                                     fdp.ConsumeUnicodeNoSurrogates(
                                     fdp.ConsumeIntInRange(0, 1000)))
  fold_list = fdp.ConsumeIntList(fdp.ConsumeIntInRange(1, 100), 4)
  toolz.sandbox.parallel.fold(add,
                              fold_list,
                              chunksize=fdp.ConsumeIntInRange(2, 100),
                              map=map)


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
