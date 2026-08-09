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

import os
import sys
import atheris

from pyparsing import (
    Literal,
    Word,
    ZeroOrMore,
    Group,
    Dict,
    Suppress,
    ParseException,
)

def dict_parse_generator(fdp):
    """Generate random parser"""
    curr = Literal("f")
    special_chars="[]{}/|\<>:;-="
    op_count = fdp.ConsumeIntInRange(2, 15)
    for i in range(op_count):
        operation = fdp.ConsumeIntInRange(0,4)
        if operation == 0:
            l1 = Literal(fdp.PickValueInList(list(special_chars)))
            l2 = Literal(fdp.PickValueInList(list(special_chars)))
            word = Word(fdp.ConsumeUnicodeNoSurrogates(10))
            curr = Group(Dict(ZeroOrMore(word)) + curr)
        elif operation == 1:
            word1 = Word(fdp.ConsumeUnicodeNoSurrogates(10))
            word2 = Word(fdp.ConsumeUnicodeNoSurrogates(10))
            curr = Group(Dict(OneOrMore(word1, word2)) + curr)
        elif operation == 2:
            curr = curr + Word(fdp.ConsumeUnicodeNoSurrogates(10))
        elif operation == 3:
            curr = curr + Suppress(fdp.ConsumeUnicodeNoSurrogates(2))
        else:
            word1 = Word(fdp.ConsumeUnicodeNoSurrogates(10))
            word2 = Word(fdp.ConsumeUnicodeNoSurrogates(10))
            curr = Group(Dict(OneOrMore(word1, word2)) + curr)
    return Dict(curr)


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    try:
        bnf = dict_parse_generator(fdp)
    except:
        return
    
    try:
        tokens = bnf.parseString(fdp.ConsumeUnicodeNoSurrogates(1024))
    except ParseException:
        pass
    except TypeError as e:
        # Catch the TypeError exception from here:
        # https://github.com/pyparsing/pyparsing/blob/d93930308f7fe79f2290812074f62a472c83db59/pyparsing/core.py#L5674
        if "could not extract dict values from parsed results" in str(e): 
            pass
        else:
            raise e


def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
