#!/usr/bin/python3
# Copyright 2024 Google LLC
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
    import evaluate


@atheris.instrument_func
def TestInputOne(data):
    fdp = atheris.FuzzedDataProvider(data)
    all_modules = evaluate.list_evaluation_modules()

    try:
        for count in range(fdp.ConsumeIntInRange(1, 5)):
            module = evaluate.load(fdp.PickValueInList(all_modules))
            total_item = fdp.ConsumeIntInRange(1, 5)
            predictions = _generate_random_list_of_dict(fdp, total_item)
            referencess = _generate_random_list_of_dict(fdp, total_item)
            module.compute(predictions=predictions, references=references)
    except Exception:
        return


def _generate_random_dict(fdp):
    map = dict()

    for count in range(fdp.ConsumeIntInRange(1, 5)):
        map[fdp.ConsumeUnicodeNoSurrogates(1024)] = fdp.ConsumeUnicodeNoSurrogates(1024)

    map["id"] = fdp.ConsumeUnicodeNoSurrogates(1024)

    return map


def _generate_random_list(fdp, total):
    return_list = list()

    for count in range(item):
        return_list.append(_generate_random_dict(fdp))

    return return_list


if __name__ == '__main__':
    atheris.Setup(sys.argv, TestInputOne)
    atheris.Fuzz()
