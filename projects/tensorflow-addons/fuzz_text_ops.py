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
#
##########################################################################
"""Module for hitting the native text modules"""
import sys
import atheris


# Instrument selected imports rather than atheris.instrument_all() since the
# python package will have a huge amount of code and instrument_all() will
# take many minutes to complete.
with atheris.instrument_imports():
  import numpy as np
  import tensorflow as tf
  from tensorflow_addons import text


@atheris.instrument_func
def fuzz_parse_time(data):
  fdp = atheris.FuzzedDataProvider(data)

  formats = [
      'SECOND', 'MILLISECOND', 'MICROSECOND', 'NANOSECOND',
      fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(1, 32))
  ]
  try:
    text.parse_time(time_string=fdp.ConsumeUnicodeNoSurrogates(
        fdp.ConsumeIntInRange(1, 1024)),
                    time_format=fdp.ConsumeUnicodeNoSurrogates(
                        fdp.ConsumeIntInRange(1, 1024)),
                    output_unit=fdp.PickValueInList(formats))
  except tf.errors.InvalidArgumentError:
    pass


@atheris.instrument_func
def fuzz_skip_gram(data):
  fdp = atheris.FuzzedDataProvider(data)

  input_bytes = []
  for idx in range(fdp.ConsumeIntInRange(1, 100)):
    input_bytes.append(fdp.ConsumeBytes(fdp.ConsumeIntInRange(1, 64)))
  input_tensor = tf.constant(input_bytes)

  keys_inp = []
  for idx in range(5):
    keys_inp.append(fdp.ConsumeBytes(fdp.ConsumeIntInRange(1, 16)))
  keys = tf.constant(keys_inp)
  values = tf.constant([0, 1, 2, 3, 4], tf.dtypes.int64)

  tf.lookup.StaticHashTable(tf.lookup.KeyValueTensorInitializer(keys, values),
                            -1)
  no_table_output = text.skip_gram_ops._filter_input(
      input_tensor=input_tensor,
      vocab_freq_table=None,
      vocab_min_count=None,
      vocab_subsampling=None,
      corpus_size=None,
      seed=None,
  )


@atheris.instrument_func
def TestOneInput(data):
  fuzz_parse_time(data)
  try:
    fuzz_skip_gram(data)
  except (tf.errors.FailedPreconditionError, UnicodeDecodeError):
    pass


def main():
  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
