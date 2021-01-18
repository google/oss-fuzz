#!/usr/bin/python3
# Copyright 2021 Google LLC
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

import os
import sys
import atheris

from jsonschema import validate
import json

def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    schema_str = fdp.ConsumeUnicode(sys.maxsize)
    instance_str = fdp.ConsumeUnicode(sys.maxsize)

    # Get two random dictionaries
    try:
        schema = json.loads("{" + schema_str + "}")
        instance = json.loads("{" + instance_str + "}")
    except:
        return

    try:
        validate(instance=instance, schema=schema)
    except jsonschema.exceptions.ValidationError:
        None
    except jsonschema.exceptions.SchemaError:
        None

def main():
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
