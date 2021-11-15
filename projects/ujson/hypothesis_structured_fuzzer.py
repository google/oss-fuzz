#!/usr/bin/python3

# Copyright 2021 Zac Hatfield-Dodds
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

"""This fuzzer is an example harness using Hypothesis for structured inputs.

It would be possible, though more difficult, to write this test in terms
of Atheris' `FuzzedDataProvider` instead of Hypothesis strategies.

As well as defining structured inputs however, the call to
`test_ujson_roundtrip()` will replay, deduplicate, and minimize any known
failing examples from previous runs - which is great when debugging.
Hypothesis uses a separate cache to Atheris/LibFuzzer seeds, so this is
strictly complementary to your traditional fuzzing workflow.

For more details on Hypothesis, see:
https://hypothesis.readthedocs.io/en/latest/data.html
https://hypothesis.readthedocs.io/en/latest/details.html#use-with-external-fuzzers
"""

import sys
import atheris
import ujson
from hypothesis import given, strategies as st

# We could define all these inline within the call to @given(),
# but it's a bit easier to read if we name them here instead.
JSON_ATOMS = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-(2 ** 63), max_value=2 ** 63 - 1),
    st.floats(allow_nan=False, allow_infinity=False),
    st.text(),
)
JSON_OBJECTS = st.recursive(
    base=JSON_ATOMS,
    extend=lambda inner: st.lists(inner) | st.dictionaries(st.text(), inner),
)
UJSON_ENCODE_KWARGS = {
    "ensure_ascii": st.booleans(),
    "encode_html_chars": st.booleans(),
    "escape_forward_slashes": st.booleans(),
    "sort_keys": st.booleans(),
    "indent": st.integers(0, 20),
}


@given(obj=JSON_OBJECTS, kwargs=st.fixed_dictionaries(UJSON_ENCODE_KWARGS))
@atheris.instrument_func
def test_ujson_roundtrip(obj, kwargs):
    """Check that all JSON objects round-trip regardless of other options."""
    assert obj == ujson.decode(ujson.encode(obj, **kwargs))


if __name__ == "__main__":
    # Running `pytest hypothesis_structured_fuzzer.py` will replay, deduplicate,
    # and minimize any failures discovered by earlier runs or by OSS-Fuzz, or
    # briefly search for new failures if none are known.
    # Or, when running via OSS-Fuzz, we'll execute it via the fuzzing hook:
    atheris.Setup(sys.argv, atheris.instrument_func(test_ujson_roundtrip.hypothesis.fuzz_one_input))
    atheris.Fuzz()
