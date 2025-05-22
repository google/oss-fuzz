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

import atheris
import sys

import google.cloud.logging_v2._helpers as helpers
import google.cloud.logging_v2.handlers._helpers as handlers_helpers


def TestInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    op = fdp.ConsumeIntInRange(0, 4)
    if op == 0:
        helpers._normalize_severity(fdp.ConsumeInt(fdp.ConsumeIntInRange(0, 512)))
    elif op == 1:
        helpers._add_defaults_to_filter(fdp.ConsumeUnicodeNoSurrogates(40))
    elif op == 2:
        handlers_helpers._parse_trace_parent(fdp.ConsumeUnicodeNoSurrogates(300))
    else:
        handlers_helpers._parse_xcloud_trace(fdp.ConsumeUnicodeNoSurrogates(300))

def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestInput, enable_python_coverage=True)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
