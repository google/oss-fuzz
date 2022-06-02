#!/usr/bin/python3

# Copyright 2021 Google LLC
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
import os
from ansible.config.base_yml import base_yaml
from ansible.config.ansible_builtin_runtime_yml import builtin_runtime_yaml

def TestOneInput(data):

    # Create string with test input
    fdp = atheris.FuzzedDataProvider(data)
    original = fdp.ConsumeUnicode(sys.maxsize)

    # Split up string
    # First part is used for Task.load()
    # Second part is used for TaskInclude.load()
    if len(original) % 2 != 0:
        return
    half_length = len(original)//2
    first_half = original[0:half_length]
    second_half = original[half_length:-1]
    
    # Create base yaml
    with open("/tmp/base.yml", "w+") as f:
        f.write(base_yaml)
    
    # Create runtime yaml
    with open("/tmp/ansible_builtin_runtime.yml", "w+") as f:
        f.write(builtin_runtime_yaml)

    # These imports must be placed after base.yml
    # and ansible_builtin_runtime.yml are created
    from ansible.playbook.task import Task
    from ansible.playbook.task_include import TaskInclude    
    
    try:
        parent_task_ds = {'debug': first_half}
        parent_task = Task.load(parent_task_ds)

        # Create test file
        with open("include_test.yml", "w+") as f:
            f.write(second_half)
        
        task_ds = {'include': 'include_test.yml'}
        loaded_task = TaskInclude.load(task_ds, task_include=parent_task)
    except Exception:
        return     
    return

def main():
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()

if __name__ == "__main__":
    main()