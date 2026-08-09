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
import requests
import httpretty


def test_one(input_data):
  fdp = atheris.FuzzedDataProvider(input_data)

  # Enable httpretty
  httpretty.enable(verbose=True, allow_net_connect=False)

  # Create arguments
  http_body = fdp.ConsumeUnicodeNoSurrogates(sys.maxsize)
  if fdp.ConsumeBool():
    header_dict = {
        fdp.ConsumeUnicodeNoSurrogates(24): fdp.ConsumeUnicodeNoSurrogates(24),
        fdp.ConsumeUnicodeNoSurrogates(24): fdp.ConsumeUnicodeNoSurrogates(24),
        fdp.ConsumeUnicodeNoSurrogates(24): fdp.ConsumeUnicodeNoSurrogates(24),
        fdp.ConsumeUnicodeNoSurrogates(24): fdp.ConsumeUnicodeNoSurrogates(24)
    }
  else:
    header_dict = None

  # Pass random arguments to register_uri and ensure we can get it
  try:
    httpretty.register_uri(httpretty.GET,
                           "http://fuzzing.com/",
                           body=http_body,
                           content_type=fdp.ConsumeUnicodeNoSurrogates(32),
                           adding_headers=header_dict)
    response = requests.get('http://fuzzing.com')
  except httpretty.HTTPrettyError:
    pass

  httpretty.reset()


if __name__ == "__main__":
  atheris.instrument_all()
  atheris.Setup(sys.argv, test_one)
  atheris.Fuzz()
