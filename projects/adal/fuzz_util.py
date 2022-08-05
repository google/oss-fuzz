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
     from adal.util import *

def TestInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    is_http_success(fdp.ConsumeInt(10))

    class DummyClass(object):
        _call_context = {
            'log_context':{'correlation_id':fdp.ConsumeString(20)},
            'options':{'http':{
                fdp.ConsumeString(10):fdp.ConsumeString(100),
                fdp.ConsumeString(10):fdp.ConsumeString(100),
                fdp.ConsumeString(10):fdp.ConsumeString(100)
            }}
        }

        def geturl(self):
           return fdp.ConsumeString(100)

    create_request_options(DummyClass(),{
        fdp.ConsumeString(10):fdp.ConsumeString(100),
        fdp.ConsumeString(10):fdp.ConsumeString(100),
        fdp.ConsumeString(10):fdp.ConsumeString(100),
        'headers':{
            fdp.ConsumeString(10):fdp.ConsumeString(100),
            fdp.ConsumeString(10):fdp.ConsumeString(100),
            fdp.ConsumeString(10):fdp.ConsumeString(100)
        }
    })

    copy_url(fdp.ConsumeString(100))
    copy_url(DummyClass())

    base64_urlsafe_decode(fdp.ConsumeString(100))

def main():
    atheris.Setup(sys.argv, TestInput, enable_python_coverage=True)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
