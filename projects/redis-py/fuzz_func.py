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
    from redis.client import *

def dummy_callback(obj):
    pass

def TestInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    timestamp_to_datetime(fdp.ConsumeString(20))
    timestamp_to_datetime(fdp.ConsumeInt(8))
    timestamp_to_datetime(fdp.ConsumeFloat())

    string_keys_to_dict("('%s','%s','%s')"%(fdp.ConsumeString(20),fdp.ConsumeString(20),fdp.ConsumeString(20)),dummy_callback)
    string_keys_to_dict(fdp.ConsumeString(60),dummy_callback)

    parse_debug_object(fdp.ConsumeString(20))
    parse_debug_object(fdp.ConsumeUnicode(20))
    parse_debug_object(fdp.ConsumeBytes(20))

    parse_object(fdp.ConsumeString(20),fdp.ConsumeString(20))
    parse_object(fdp.ConsumeUnicode(20),fdp.ConsumeUnicode(20))
    parse_object(fdp.ConsumeBytes(20),fdp.ConsumeBytes(20))
    parse_object(fdp.ConsumeInt(8),fdp.ConsumeBytes(20))
    parse_object(fdp.ConsumeInt(8),"idletime")
    parse_object(fdp.ConsumeFloat(),"idletime")
    try:
        parse_object(fdp.ConsumeString(20),"idletime")
    except ValueError as e:
        if "invalid literal for int() with base 10" not in str(e):
            raise e
    parse_object(fdp.ConsumeBool(),"idletime")

    response_str = """
        %s:%s
        %s:%s
        %s:%s
        %s:%d
        %s:%f
        %s:%d
    """%(
        fdp.ConsumeString(20),fdp.ConsumeString(20),
        fdp.ConsumeString(20),fdp.ConsumeUnicode(20),
        fdp.ConsumeString(20),fdp.ConsumeBytes(20),
        fdp.ConsumeString(20),fdp.ConsumeInt(8),
        fdp.ConsumeString(20),fdp.ConsumeFloat(),
        fdp.ConsumeString(20),fdp.ConsumeBool(),
    )

    parse_info(fdp.ConsumeString(20))
    parse_info(fdp.ConsumeUnicode(20))
    parse_info(fdp.ConsumeBytes(20))
    parse_info(response_str)

    cid = CaseInsensitiveDict({
        fdp.ConsumeString(10):fdp.ConsumeUnicode(10),
        fdp.ConsumeString(10):fdp.ConsumeBytes(10),
        fdp.ConsumeString(10):fdp.ConsumeInt(8),
        fdp.ConsumeString(10):fdp.ConsumeFloat(),
        fdp.ConsumeString(10):fdp.ConsumeBool()
    })
    fdp.ConsumeString(10) in cid
    cid.popitem()
    cid.get(fdp.ConsumeString(10))
    cid[fdp.ConsumeString(10)] = fdp.ConsumeString(5)
    cid.update({
        fdp.ConsumeString(10):fdp.ConsumeUnicode(10),
        fdp.ConsumeString(10):fdp.ConsumeBytes(10),
        fdp.ConsumeString(10):fdp.ConsumeInt(8),
        fdp.ConsumeString(10):fdp.ConsumeFloat(),
        fdp.ConsumeString(10):fdp.ConsumeBool() 
    })

def main():
    atheris.Setup(sys.argv, TestInput, enable_python_coverage=True)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
