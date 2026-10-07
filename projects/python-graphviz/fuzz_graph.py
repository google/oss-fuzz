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
"""Create a random graph and pass it through the whole rendering process."""
import sys
import atheris
import graphviz


def TestOneInput(data):
  fdp = atheris.FuzzedDataProvider(data)
  g = graphviz.Graph('G', filename='/tmp/process.gv', engine='sfdp')
  for i in range(fdp.ConsumeIntInRange(1, 8196)):
    g.edge(fdp.ConsumeUnicodeNoSurrogates(24),
           fdp.ConsumeUnicodeNoSurrogates(24))
  try:
    g.view()
  except (
      NotImplementedError,
      graphviz.backend.execute.CalledProcessError,
      graphviz.backend.execute.ExecutableNotFound,
  ):
    pass


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
