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

import io
import botocore
from botocore import serialize
from botocore.model import ServiceModel


def TestOneInput(data):
  fdp = atheris.FuzzedDataProvider(data)
  protocols = [
    'rest-xml', 'json', 'query'
  ]
  protocol_str = protocols[fdp.ConsumeIntInRange(0, len(protocols)-1)]

  # Simple model with a single shape of type blob
  model = {
    'metadata': {'protocol': protocol_str, 'apiVersion': '2022-01-01'},
    'documentation': '',
    'operations': {
      'FuzzOperation': {
        'name': 'FuzzOperation',
        'http': {
          'method': 'POST',
          'requestUri': '/',
        },
        'input': {'shape': 'FuzzInputShape'},
      }
    },
    'shapes': {
      'FuzzInputShape': {
        'type': 'structure',
        'members': {
          'Blob': {'shape': 'BlobType'},
        },
      },
      'BlobType': {
        'type': 'blob',
      },
    },
  }

  service_model = ServiceModel(model)
  request_serializer = serialize.create_serializer(
    service_model.metadata['protocol']
  )
  body = io.BytesIO(data)
  try:
    request_serializer.serialize_to_request(
      body,
      service_model.operation_model('FuzzOperation')
    )
  except botocore.exceptions.ParamValidationError:
    pass


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
  atheris.Fuzz()


if __name__ == "__main__":
  main()

