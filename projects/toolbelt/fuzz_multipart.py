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

import io
import mock
import requests
from requests_toolbelt.multipart import decoder


def TestOneInput(data):
  fdp = atheris.FuzzedDataProvider(data)

  response = mock.NonCallableMagicMock(spec=requests.Response)
  response.headers = {
    'content-type': 'multipart/related; boundary="samp1"'
  }
  response.content = io.BytesIO(data).getvalue()
  try:
    decoder.MultipartDecoder.from_response(response)
  except decoder.ImproperBodyPartContentException:
    pass
  except decoder.NonMultipartContentTypeException:
    pass
  except UnicodeDecodeError:
    pass


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
