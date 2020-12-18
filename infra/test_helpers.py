# Copyright 2020 Google LLC
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
"""Contains convenient helpers for writing tests."""

import contextlib
import os
import shutil
import tempfile
from unittest import mock


def patch_environ(testcase_obj, env=None):
  """Patch environment."""
  if env is None:
    env = {}

  patcher = mock.patch.dict(os.environ, env)
  testcase_obj.addCleanup(patcher.stop)
  patcher.start()


@contextlib.contextmanager
def temp_dir_copy(directory):
  """Context manager that yields a temporary copy of |directory|."""
  with tempfile.TemporaryDirectory() as temp_dir:
    temp_copy_path = os.path.join(temp_dir, os.path.basename(directory))
    shutil.copytree(directory, temp_copy_path)
    yield temp_copy_path
