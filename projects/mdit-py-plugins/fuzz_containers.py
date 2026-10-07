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
"""Parse markdown using one of the mdit-py-plugins plugins."""
import sys
import atheris

import markdown_it
import mdit_py_plugins
from mdit_py_plugins.container import container_plugin


def TestOneInput(data):
  fdp = atheris.FuzzedDataProvider(data)
  md = markdown_it.MarkdownIt().use(container_plugin, "fuzz")
  md.parse(fdp.ConsumeUnicodeNoSurrogates(sys.maxsize))


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
