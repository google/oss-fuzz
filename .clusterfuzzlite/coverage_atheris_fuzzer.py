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

import json
import os
import sys
from unittest import mock

# Fix #3: Validate paths before appending
_parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_cifuzz_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'cifuzz')

if _parent_dir not in sys.path:
    sys.path.append(_parent_dir)

if os.path.isdir(_cifuzz_dir) and _cifuzz_dir not in sys.path:
    sys.path.append(_cifuzz_dir)

# Fix #4: instrument_imports must wrap ALL target imports at the top
import atheris

with atheris.instrument_imports():
    import get_coverage

REPO_PATH = '/src/curl'
PROJECT_NAME = 'curl'

# Fix #2: Use mock.patch as a decorator or keep the mock active for the
# lifetime of the object if needed. Here we patch at module level so
