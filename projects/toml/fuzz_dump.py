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
import atheris_dict

import toml


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    # Pick from a random set of encoders
    ENCODERS = [
        toml.TomlEncoder(preserve=fdp.ConsumeBool()),  # Optional formatting argument
        toml.TomlPreserveInlineDictEncoder(),
        toml.TomlArraySeparatorEncoder(separator=",\t"),
        toml.TomlPreserveCommentEncoder(),
        toml.TomlPathlibEncoder(),
        None,
    ]

    # Generate a random dictionary object
    fuzz_dict = atheris_dict.random_dict(10, 10, fdp_generator=fdp)

    with io.StringIO("") as outfile:
        result = toml.encoder.dump(fuzz_dict, outfile, fdp.PickValueInList(ENCODERS))


def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
