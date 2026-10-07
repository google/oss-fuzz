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
import mock
with atheris.instrument_imports():
    from google.cloud import error_reporting as error

class SampleRequest(object):
    def __init__(self, url, method, user_agent, referrer, remote_addr):
        self.url = url
        self.method = method
        self.user_agent = user_agent
        self.referrer = referrer
        self.remote_addr = remote_addr

def TestInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    request = SampleRequest(
        "http://127.0.0.1",
        "GET" if fdp.ConsumeBool() else "POST",
        mock.Mock(string=fdp.ConsumeString(100)),
        fdp.ConsumeString(100),
        "127.0.0.1"
    )
    error.util.build_flask_context(request)

def main():
    atheris.Setup(sys.argv, TestInput, enable_python_coverage=True)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
