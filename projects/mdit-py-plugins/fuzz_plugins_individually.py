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
from mdit_py_plugins.attrs import attrs_plugin
from mdit_py_plugins.admon import admon_plugin
from mdit_py_plugins.anchors import anchors_plugin
from mdit_py_plugins.amsmath import amsmath_plugin
from mdit_py_plugins.colon_fence import colon_fence_plugin
from mdit_py_plugins.deflist import deflist_plugin
from mdit_py_plugins.dollarmath import dollarmath_plugin
from mdit_py_plugins.field_list import fieldlist_plugin
from mdit_py_plugins.footnote import footnote_plugin
from mdit_py_plugins.front_matter import front_matter_plugin
from mdit_py_plugins.myst_blocks import myst_block_plugin
from mdit_py_plugins.myst_role import myst_role_plugin
from mdit_py_plugins.substitution import substitution_plugin
from mdit_py_plugins.tasklists import tasklists_plugin
from mdit_py_plugins.texmath import texmath_plugin
from mdit_py_plugins.wordcount import wordcount_plugin


def TestOneInput(data):
  fdp = atheris.FuzzedDataProvider(data)
  plugins = [
      attrs_plugin,
      admon_plugin,
      anchors_plugin,
      amsmath_plugin,
      colon_fence_plugin,
      deflist_plugin,
      dollarmath_plugin,
      fieldlist_plugin,
      footnote_plugin,
      front_matter_plugin,
      myst_block_plugin,
      myst_role_plugin,
      substitution_plugin,
      tasklists_plugin,
      texmath_plugin,
      wordcount_plugin
  ]
  plugin_to_use = fdp.PickValueInList(plugins)
  md = markdown_it.MarkdownIt().use(plugin_to_use)
  md.parse(fdp.ConsumeUnicodeNoSurrogates(sys.maxsize))


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
