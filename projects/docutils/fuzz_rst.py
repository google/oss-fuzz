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

import sys
import atheris

from docutils.parsers.rst import Parser
from docutils.frontend import get_default_settings
from docutils.utils import new_document
from docutils import ApplicationError


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    parser = Parser()
    settings = get_default_settings(Parser)
    settings.warning_stream = ""
    doc = new_document(fdp.ConsumeUnicodeNoSurrogates(64), settings.copy())
    try:
        parser.parse(fdp.ConsumeUnicodeNoSurrogates(sys.maxsize), doc)
    except ApplicationError:
        pass


def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()

