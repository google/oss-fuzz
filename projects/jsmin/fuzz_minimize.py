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
from jsmin import jsmin


def TestOneInput(data):
    with open('myfile.js', "wb") as js_file:
        js_file.write(data)

    with open('myfile.js') as js_file:
        try:
            minified = jsmin(js_file.read())
        except UnicodeDecodeError:
            pass


def main():
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.instrument_all()
    atheris.Fuzz()

if __name__ == "__main__":
    main()
