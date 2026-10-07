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
import mock
import atheris

import google.auth.credentials
from google.cloud.firestore_v1.query import CollectionGroup
from google.cloud.firestore_v1.client import Client


def TestOneInput(data):
  fdp = atheris.FuzzedDataProvider(data)
  credentials = mock.Mock(spec=google.auth.credentials.Credentials)
  client = Client(
    project="fuzz_project",
    credentials = credentials
  )
  try:
    parent = client.collection(fdp.ConsumeString(100))
  except ValueError:
    return
  
  query = CollectionGroup(parent).limit(fdp.ConsumeIntInRange(1, 10))
  try:
    _ = list(query.get_partitions(fdp.ConsumeIntInRange(1, 50)))
  except ValueError:
    pass


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
  atheris.Fuzz()

if __name__ == "__main__":
  main()
