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

import os
import sys
import atheris

from c7n import exceptions, utils



def TestOneInput(data):
    """Fuzz encode and decode"""
    fdp = atheris.FuzzedDataProvider(data)
    try:
        qp = utils.QueryParser.parse(fdp.ConsumeUnicodeNoSurrogates(1024))
    except exceptions.PolicyValidationError:
        pass

    c7njme = utils.C7NJMESPathParser()
    try:
        c7njme.parse(fdp.ConsumeUnicodeNoSurrogates(1024))
    except:
        pass


def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
