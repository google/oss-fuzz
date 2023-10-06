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

import io
import sys
import atheris

# Libraries used as part of the test
import dictgen
from numpy import array, float64, int32
import pathlib
from random import randint

import toml
from toml import ordered as toml_ordered

def random_path(**kwargs):
    return pathlib.Path(f"/{dictgen.random_string()}")

def random_inlinetabledict(**kwargs):
    class TestDict(dict, toml.decoder.InlineTableDict):
        pass
    
    val_generators = kwargs["val_generators"]
    key_generators = kwargs["key_generators"]
    nested_generators = kwargs["nested_generators"]
    max_height = kwargs["max_height"]
    max_depth = kwargs["max_depth"]

    all_generators = val_generators + nested_generators

    target = TestDict()
    for i in range(randint(0, max_height)):
        # If we are at a top level depth don't allow any nested generators
        if max_depth > 2:
            target[key_generators[randint(0, len(key_generators) - 1)](**kwargs)] = all_generators[randint(0, len(all_generators) - 1)](**kwargs)
        else:
            target[key_generators[randint(0, len(key_generators) - 1)](**kwargs)] = val_generators[randint(0, len(val_generators) - 1)](**kwargs)
    return target

def random_numpy(**kwargs):
    df = {
        dictgen.random_string() : array([1, .3], dtype=float64),
        dictgen.random_string(): array([1, 3], dtype=int32)
    }
    return df

def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    # Pick from a random set of encoders
    ENCODERS = [
        toml.TomlEncoder(preserve=fdp.ConsumeBool()),  # Optional formatting argument
        toml.TomlPreserveInlineDictEncoder(),
        toml.TomlArraySeparatorEncoder(),
        toml.TomlPreserveCommentEncoder(),
        toml.TomlPathlibEncoder(),
        toml_ordered.TomlOrderedEncoder(),
        toml.TomlNumpyEncoder(),
        None,
    ]

    # Generate a random dictionary object
    fuzz_dict = dictgen.generate(
        key_generators=(
            dictgen.random_string,
        ),
        val_generators=(
            dictgen.random_int,
            dictgen.random_float,
            dictgen.random_string,
            dictgen.random_datetime,
            random_path,
            random_numpy
        ),
        nested_generators=(
            dictgen.random_dict,
            dictgen.random_array,
            random_inlinetabledict
        ),
        rand_seed=fdp.ConsumeInt(32)
    )

    try:
        with io.StringIO("") as outfile:
            result = toml.encoder.dump(fuzz_dict, outfile, fdp.PickValueInList(ENCODERS))
    except TypeError:
        pass

def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
