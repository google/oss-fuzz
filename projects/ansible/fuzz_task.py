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
"""Tests ansible.playbook.task"""

import atheris
import sys
with atheris.instrument_imports():
    from ansible.errors import (
        AnsibleError,
        AnsibleParserError,
        AnsibleUndefinedVariable
    )
    from ansible.playbook.task import Task

@atheris.instrument_func
def TestInput(input_bytes):
    if len(input_bytes) < 5:
        return

    fdp = atheris.FuzzedDataProvider(input_bytes)

    try:
        task = Task.load(
            {
                'name': fdp.ConsumeString(10),
                'shell': fdp.ConsumeString(10),
                'action': fdp.ConsumeString(10),
                'debug': fdp.ConsumeString(10)
            }
        )

        task.get_vars()
        task.get_include_params()
        task.copy()
        data = task.serialize()
        task.deserialize(data)
    except (
        AnsibleError,
        AnsibleParserError,
        AnsibleUndefinedVariable
    ) as e:
        pass

def main():
    atheris.Setup(sys.argv, TestInput, enable_python_coverage=True)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
