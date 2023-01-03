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
#
################################################################################
"""Catches vulnerable yaml desrializations that can potentially lead to
arbitrary code execution."""
from pysecsan import sanlib

try:
  import yaml
# pylint: disable=broad-except
except Exception:
  pass


def hook_pre_exec_pyyaml_load(stream, loader):
  """Hook for pyyaml.load_yaml.

    Exits if the loader is unsafe or vanilla loader and the stream passed
    to the loader is controlled by the fuzz data
    """
  # Ensure loader is the unsafe loader or vanilla loader
  if loader not in (yaml.loader.Loader, yaml.loader.UnsafeLoader):
    return

  # Check for exact taint in stream
  if sanlib.is_exact_taint(stream):
    msg = (
        'Yaml deserialization issue.\n'
        'Unsafe deserialization can be used to execute arbitrary commands.\n')
    sanlib.abort_with_issue(msg, 'Yaml deserialisation')
