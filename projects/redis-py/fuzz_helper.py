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
    from redis.commands.helpers import *

def TestInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    temp_list = [
        fdp.ConsumeString(10),
        fdp.ConsumeUnicode(10),
        fdp.ConsumeBytes(10)
    ]

    temp_dict_list = [
        [fdp.ConsumeString(10),fdp.ConsumeUnicode(10)],
        [fdp.ConsumeString(10),fdp.ConsumeBytes(10)],
        [
            fdp.ConsumeString(10),
            [
                fdp.ConsumeString(10),
                fdp.ConsumeUnicode(10),
                fdp.ConsumeString(10),
                fdp.ConsumeBytes(10),
                fdp.ConsumeString(10),
                [
                     fdp.ConsumeString(10),fdp.ConsumeInt(8),
                     fdp.ConsumeString(10),fdp.ConsumeFloat()
                ],
                [fdp.ConsumeString(10),fdp.ConsumeBool()]
            ]
        ]
    ]

    temp_list = list_or_args(fdp.ConsumeString(10),temp_list)
    temp_list = list_or_args(fdp.ConsumeUnicode(10),temp_list)
    temp_list = list_or_args(fdp.ConsumeBytes(10),temp_list)
    temp_list = list_or_args([fdp.ConsumeString(10)],temp_list)
    temp_list = list_or_args([fdp.ConsumeUnicode(10)],temp_list)
    temp_list = list_or_args([fdp.ConsumeBytes(10)],temp_list)

    delist(temp_list)
    parse_to_list(temp_list)

    temp_dict = parse_to_dict(temp_dict_list)
    decode_dict_keys(temp_dict)

    nativestr(fdp.ConsumeString(10))
    nativestr(fdp.ConsumeUnicode(10))
    nativestr(fdp.ConsumeBytes(10))
    random_string(fdp.ConsumeInt(8))
    quote_string(fdp.ConsumeString(20))
    stringify_param_value(fdp.ConsumeString(10))
    stringify_param_value(fdp.ConsumeUnicode(10))
    stringify_param_value(fdp.ConsumeBytes(10))
    stringify_param_value(temp_list)
    stringify_param_value(temp_dict)

def main():
    atheris.Setup(sys.argv, TestInput, enable_python_coverage=True)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
