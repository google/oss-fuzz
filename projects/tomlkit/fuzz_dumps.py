#!/usr/bin/python3
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
import atheris
import sys
import tomlkit
import dictgen


def test_one_input(input_bytes: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(input_bytes)
    test_data = dictgen.generate(
        max_height=5,
        max_depth=10,
        key_generators=(
            dictgen.random_string,
        ),
        val_generators=(
            dictgen.random_string,
            dictgen.random_bool,
            dictgen.random_int,
            dictgen.random_datetime,
            dictgen.random_float
        ),
        rand_seed=fdp.ConsumeInt(32)
    )
    tomlkit.api.dumps(test_data, sort_keys=fdp.ConsumeBool())


def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
