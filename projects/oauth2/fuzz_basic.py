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

import atheris
import sys

with atheris.instrument_imports():
    from oauth2client.client import OAuth2WebServerFlow
    from oauth2client.client import OAuth2DeviceCodeError

def TestInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    CLIENT_ID = fdp.ConsumeString(100)
    CLIENT_SECRET = fdp.ConsumeString(100)
    SCOPES = ("https://localhost:%d/%s"%(
         fdp.ConsumeIntInRange(1000,65535),
         fdp.ConsumeString(50)
    ))

    try:
         flow = OAuth2WebServerFlow(CLIENT_ID, CLIENT_SECRET, " ".join(SCOPES))
         flow_info = flow.step1_get_device_and_user_codes()
         credentials = flow.step2_exchange(device_flow_info=flow_info)
    except OAuth2DeviceCodeError as e:
        pass 

def main():
    atheris.Setup(sys.argv, TestInput, enable_python_coverage=True)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
