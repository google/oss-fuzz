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

import platformdirs


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    targets = [
        platformdirs.user_data_dir,
        platformdirs.site_data_dir,
        platformdirs.user_config_dir,
        platformdirs.site_config_dir,
        platformdirs.user_cache_dir,
        platformdirs.user_state_dir,
        platformdirs.user_log_dir,
        platformdirs.user_runtime_dir,
        platformdirs.user_data_path,
        platformdirs.site_data_path,
        platformdirs.user_config_path,
        platformdirs.site_config_path,
        platformdirs.user_cache_path,
        platformdirs.user_state_path,
        platformdirs.user_log_path,
        platformdirs.user_runtime_path
    ]

    target = targets[fdp.ConsumeIntInRange(0, len(targets))-1]
    target(
        fdp.ConsumeUnicodeNoSurrogates(100),
        fdp.ConsumeUnicodeNoSurrogates(100),
        fdp.ConsumeUnicodeNoSurrogates(100),
        fdp.ConsumeBool()
    )


def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
