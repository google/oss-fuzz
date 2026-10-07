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
"""Tests lib/ansible/parsing/"""

import atheris
import sys
with atheris.instrument_imports():
    from ansible.errors import AnsibleError, AnsibleParserError
    from ansible.parsing import splitter
    from ansible.parsing import quoting


@atheris.instrument_func
def TestInput(input_bytes):
    fdp = atheris.FuzzedDataProvider(input_bytes)

    try:
        # Test splitter module
        args = splitter.split_args(fdp.ConsumeString(50))
        splitter.join_args(args)

        # Test quoting module
        quoting.is_quoted(fdp.ConsumeString(10))
        quoting.unquote(fdp.ConsumeString(10))
    except (AnsibleError, AnsibleParserError) as e:
        pass


def main():
   atheris.Setup(sys.argv, TestInput, enable_python_coverage=True)
   atheris.Fuzz()


if __name__ == "__main__":
   main()
