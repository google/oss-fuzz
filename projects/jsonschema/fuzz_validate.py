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

import jsonschema
from hypothesis import given, strategies as st

PRIM = st.one_of(
    st.booleans(),
    st.integers(min_value=-(2 ** 63), max_value=2 ** 63 - 1),
    st.floats(allow_nan=False, allow_infinity=False),
    st.text(),
)
DICT = st.recursive(
    base=st.dictionaries(st.text(), PRIM),
    extend=lambda inner: st.dictionaries(st.text(), inner),
)

@given(obj1=DICT, obj2=DICT)
def test_schemas(obj1, obj2):
    try:
        jsonschema.validate(instance=obj1, schema=obj2)
    except jsonschema.exceptions.ValidationError:
        None
    except jsonschema.exceptions.SchemaError:
        None

def main():
    atheris.Setup(sys.argv,
                  test_schemas.hypothesis.fuzz_one_input,
                  enable_python_coverage=True)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
