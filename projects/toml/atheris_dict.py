# Copyright 2023 Google LLC
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
#
################################################################################

# This is a modified version of https://github.com/robtandy/randomdict which has
# been changed to
#    - Work with the atheris fuzzer
#    - Filter duplicate keys
#    - Target the TOML encoder library

import datetime
from itertools import product
from random import choice, shuffle
from typing import Callable, List
import pathlib
import sys
from toml.decoder import InlineTableDict

fdp = None


def random_int():
    return fdp.ConsumeInt(16)


def random_float():
    return fdp.ConsumeFloat()


def random_string():
    return fdp.ConsumeString(fdp.ConsumeIntInRange(0, 1024))


def random_datetime():
    return datetime.time(
        hour=fdp.ConsumeIntInRange(0, 23), minute=fdp.ConsumeIntInRange(0, 59)
    )


def random_list():
    t = fdp.ConsumeIntList(10, 16)
    for i in range(fdp.ConsumeIntInRange(0, 2)):
        # Add dictionary to hit nested arrayoftables functionality
        t.append(random_dict(2, 2))
    return t


def random_inline_table_dict():
    class TestDict(dict, InlineTableDict):
        pass

    t = TestDict()
    t[random_string()] = random_float()
    return t


def random_path():
    return pathlib.Path("/hello/world")


# Return a random set of functions from list
def _value_gen(sources: List[Callable], number: int) -> Callable:
    for _ in range(number):
        yield choice(sources)


generators = (random_int, random_float, random_string)


def random_dict(
    max_depth,
    max_height,
    generators=(
        random_int,
        random_float,
        random_string,
        random_datetime,
        random_list,
        random_inline_table_dict,
        random_path,
    ),
    generators_combinations=5,
    fdp_generator=None,
):
    # Create a handle to the fdp generator
    if fdp_generator:
        global fdp
        fdp = fdp_generator

    # Create random combinations of key and value generators
    # e.g. random_string, random_int
    generators_tuples = list(
        product(_value_gen(generators, max_height), _value_gen(generators, max_height))
    )

    # Shuffle that list
    shuffle(generators_tuples)

    # Return a dictionary item
    result = {}
    for key_gen, val_gen in generators_tuples[:generators_combinations]:
        # Filter out types that can't be used as dictionary keys
        # Currently we're filtering out valid python key types because toml throws
        # exception when using them. See issue https://github.com/uiri/toml/issues/408
        if key_gen not in [
            random_list,
            random_inline_table_dict,
            random_datetime,
            random_path,
            random_int,
            random_float,
        ]:
            # New logic to remove duplicates
            newKey = key_gen()
            if newKey not in result:
                result[key_gen()] = (
                    random_dict(
                        fdp.ConsumeIntInRange(1, max_depth - 1),
                        fdp.ConsumeIntInRange(1, max_height - 1),
                        generators,
                    )
                    if max_depth > 1 and max_height > 1
                    else val_gen()
                )
    return result
