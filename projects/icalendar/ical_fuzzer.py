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
#
################################################################################
import atheris
import sys

with atheris.instrument_imports(include=['icalendar']):
    from icalendar import Calendar

from enhanced_fdp import EnhancedFuzzedDataProvider


def TestOneInput(data):
    fdp = EnhancedFuzzedDataProvider(data)
    try:
        Calendar.from_ical(fdp.ConsumeRemainingString())
    except ValueError as e:
        if "component" in str(e) or "parse" in str(e):
            return -1
        raise e


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
