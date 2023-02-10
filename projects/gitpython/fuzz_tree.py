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
import io
import sys
import shutil
import atheris

from git.objects import Tree
from git import Repo


def TestOneInput(data):
  fdp = atheris.FuzzedDataProvider(data)
  git_dir = "/tmp/.git"
  head_file = os.path.join(git_dir, "HEAD")
  refs_dir = os.path.join(git_dir, "refs")
  common_dir = os.path.join(git_dir, "commondir")
  objects_dir = os.path.join(git_dir, "objects")

  if os.path.isdir(git_dir):
    shutil.rmtree(git_dir)

  os.mkdir(git_dir)
  with open(head_file, "w") as f:
    f.write(fdp.ConsumeUnicodeNoSurrogates(1024))
  os.mkdir(refs_dir)
  os.mkdir(common_dir)
  os.mkdir(objects_dir)

  _repo = Repo("/tmp/")

  fuzz_tree = Tree(_repo, Tree.NULL_BIN_SHA, 0, "")
  try:
    fuzz_tree._deserialize(io.BytesIO(data))
  except IndexError:
    pass


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
