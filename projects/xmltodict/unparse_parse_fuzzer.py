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
"""Test dict to xml and back with fuzzing.."""
from typing import Dict, Any, Text, List, Callable

import atheris
import logging
import sys

from collections import OrderedDict
from xmltodict import parse, unparse
from xml.parsers.expat import ExpatError

_MAX_LENGTH = 1000
_MAX_DEPTH = 500


def _gen_dict(fdp: atheris.FuzzedDataProvider, depth: int):
    """Returns a random dict for fuzzing."""
    length = fdp.ConsumeIntInRange(0, _MAX_LENGTH)
    d = OrderedDict()
    for _ in range(length):
        key_length = fdp.ConsumeIntInRange(0, _MAX_LENGTH)
        key = fdp.ConsumeString(key_length)
        d[key] = _gen_value(fdp, depth + 1)
    return d


def _gen_string(fdp: atheris.FuzzedDataProvider):
    """Returns a random string for fuzzing."""
    length = fdp.ConsumeIntInRange(0, _MAX_LENGTH)
    return fdp.ConsumeString(length)


def _gen_list(fdp: atheris.FuzzedDataProvider, depth: int):
    """Returns a random list for fuzzing."""
    length = fdp.ConsumeIntInRange(0, _MAX_LENGTH)
    return [_gen_value(fdp, depth + 1) for _ in range(length)]


def _gen_value(fdp: atheris.FuzzedDataProvider, depth: int) -> Any:
    """Returns a random value for fuzzing."""
    consume_next = [
        fdp.ConsumeBool,
        fdp.ConsumeFloat,
        lambda: fdp.ConsumeInt(4),
        lambda: _gen_string(fdp),
        lambda: None,
    ]
    # XML documents can have exactly 1 root so don't add lists when
    # depth is exactly 0.
    if 0 < depth < _MAX_DEPTH:
        consume_next.append(lambda: _gen_list(fdp, depth))

    if depth < _MAX_DEPTH:
        consume_next.append(lambda: _gen_dict(fdp, depth))
    return fdp.PickValueInList(consume_next)()


@atheris.instrument_func
def test_one_input(data: bytes):
    fdp = atheris.FuzzedDataProvider(data)
    original = OrderedDict()
    try:
        original[_gen_string(fdp)] = _gen_value(fdp, depth=0)
    except RecursionError:
        # Not interesting
        return

    try:
        # Not all fuzz-generated data is valid XML.
        xml = unparse(original)
    except (ExpatError, UnicodeEncodeError):
        return

    try:
        # FIXME: Not all unparsed XML is parsable.
        # FIXME: Why is there an _encode_ error in parse?
        final = parse(xml)  # type: OrderedDict[Text, Any]
    except (ExpatError, UnicodeEncodeError):
      return

    assert len(original) == len(final)
    for (k1,v1), (k2, v2) in zip(original.items(), final.items()):
        assert k1.strip() == k2, (k1, k2)

        if isinstance(v1, str):
            # Strings are stripped and '' becomes None.
            v1 = v1.strip() or None
        if any(isinstance(v1, t) for t in (bool, int, float)):
            # Bools and Numbers become strings.
            v1 = str(v1)
            # Capitalization of booleans is inconsistent.
            assert v1.lower() == v2.lower(), (v1, v2)
            return
        if v1 == OrderedDict():
            # Empty dict => None
            assert v2 == None
            return

        assert v1 == v2, (v1, v2)

def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()
    return 0

if __name__ == "__main__":
    sys.exit(main())
