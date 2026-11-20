#!/usr/bin/python3
# Copyright 2026 Google LLC
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
"""Fuzzes nested-submessage wrapper lifetimes across a merge.

The existing fuzz_protobuf.py target parses untrusted bytes into a freshly
constructed message. It therefore never exercises the case where application
code retains a reference to a nested submessage across a parse of untrusted
input and then merges into the intermediate message -- a pattern common in
middleware that caches a sub-message before validating a request.

This target keeps the API sequence fixed and lets the fuzzer control the wire
bytes, which is the untrusted input in that pattern.
"""

import sys
import atheris

with atheris.instrument_imports():
  import test_full_pb2
  from google.protobuf.message import DecodeError, EncodeError


@atheris.instrument_func
def TestOneInput(input_bytes):
  msg = test_full_pb2.TestMessSubMess()

  # Application retains a reference to an intermediate message and to a
  # currently-unset nested submessage beneath it. The intermediate must be
  # present before the parse; setting a scalar on it does that.
  intermediate = msg.opt_mess
  intermediate.test_int32 = 1
  retained = intermediate.test_message

  # Untrusted input is merged into the parent; it may set the nested field.
  try:
    msg.MergeFromString(input_bytes)
  except (DecodeError, ValueError):
    return

  # Application re-reads the nested field after the parse.
  refreshed = intermediate.test_message

  # A later merge is applied to the intermediate message.
  try:
    intermediate.MergeFrom(test_full_pb2.TestMessOptional())
  except (DecodeError, ValueError):
    return

  # The re-read wrapper goes out of use, then the field is read again.
  current = intermediate.test_message
  del current
  del refreshed
  try:
    _ = intermediate.test_message.test
    _ = retained.test
    # SerializePartialToString: test-full.proto is proto2 with required
    # fields, so SerializeToString would raise on nearly every input and the
    # serialization path would never be exercised.
    msg.SerializePartialToString()
  except (EncodeError, ValueError):
    return


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
