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

import sys
import atheris

with atheris.instrument_imports(enable_loader_override=False):
  import google.api.quota_pb2
  import google.api.billing_pb2
  import google.api.routing_pb2
  import google.api.log_pb2
  from google.protobuf.message import DecodeError, EncodeError


@atheris.instrument_func
def protobuf_roundtrip(proto_target, input_bytes):
  try:
    proto_target.ParseFromString(input_bytes)
  except DecodeError:
    None

  try:
    proto_target.SerializeToString()
  except EncodeError:
    None


@atheris.instrument_func
def TestOneInput(input_bytes):
  """Test ParseFromString with bytes string"""

  protobuf_roundtrip(google.api.quota_pb2.QuotaLimit(), input_bytes)
  protobuf_roundtrip(google.api.billing_pb2.Billing(), input_bytes)
  protobuf_roundtrip(google.api.routing_pb2.RoutingRule(), input_bytes)
  protobuf_roundtrip(google.api.log_pb2.LogDescriptor(), input_bytes)


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
