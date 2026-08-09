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
"""Targetting the looker-sdk"""

import os
import sys
import json
import mock
import atheris
import looker_sdk
import requests
from looker_sdk import models40 as models


# Sample configuration. We use mock to handle network communication so
# these fields are not important.
conf = """[Looker]
api_versions=3.1,4.0
base_url=https://localhost:19999
client_id=your_API3_client_id
client_secret=your_API3_client_secret
verify_ssl=true
timeout=2"""
return_dict = None
def transport_requests_mock(
  method,
  path,
  query_params=None,
  body=None,
  authenticator=None,
  transport_options=None
):
  """Returns an arbitrary dictionary string"""
  global return_dict
  r1 = looker_sdk.rtl.transport.Response(True, return_dict, 3, "utf-8")
  return r1

@atheris.instrument_func
def TestOneInput(data):
  global return_dict
  fdp = atheris.FuzzedDataProvider(data)
  s1 = fdp.ConsumeString(fdp.ConsumeIntInRange(0, 1024))
  try:
    fuzzed_dict = json.loads(s1)
  except:
    return
  if type(fuzzed_dict) is not dict:
    return

  return_dict = str.encode(s1)

  with open("looker.ini", "w") as f:
      f.write(conf)
  sdk = looker_sdk.init40("looker.ini")
  m1 = fdp.ConsumeUnicodeNoSurrogates(20)
  v1 = fdp.ConsumeUnicodeNoSurrogates(20)
  l1 = [fdp.ConsumeUnicodeNoSurrogates(20)]

  patch = mock.patch(
    "looker_sdk.rtl.requests_transport.RequestsTransport.request",
    wraps=transport_requests_mock
  )
  # Perform a set of operations
  op_count = fdp.ConsumeIntInRange(1, 10)
  with patch:
    for i in range(op_count):
      op = fdp.ConsumeIntInRange(1,3)
      if op == 1:
        try:
          query = sdk.create_query(
            body=models.WriteQuery(model=m1, view=v1, fields=l1)
          )
        except looker_sdk.rtl.serialize.DeserializeError:
          pass
      elif op == 2:
        try:
          query = sdk.create_query_task(
            body = models.WriteCreateQueryTask(
              query_id=fdp.ConsumeUnicodeNoSurrogates(10),
              source=fdp.ConsumeUnicodeNoSurrogates(10),
              results_format=looker_sdk.sdk.api40.ResultFormat.csv
            )
          )
        except looker_sdk.rtl.serialize.DeserializeError:
          pass


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
  atheris.Fuzz()

if __name__ == "__main__":
  main()
