#!/usr/bin/env python3
# Copyright 2025 Google LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Utils for snapshotting shared libraries."""

import dataclasses
import os
import pathlib
import re
import subprocess
from typing import Final, Sequence

_LD_PATH = "/usr/bin/ld.so.2"
_LD_PATH: Final[pathlib.Path] = pathlib.Path("/lib64/ld-linux-x86-64.so.2")


@dataclasses.dataclass(frozen=True)
class SharedLibrary:
  """A shared library with its name and path."""

  name: str
  path: pathlib.Path


def _parse_ld_trace_output(output: str) -> Sequence[SharedLibrary]:
  """Parses the output of `LD_TRACE_LOADED_OBJECTS=1 ld.so`."""
  if "statically linked" in output:
    return []

  # Example output:
  #       linux-vdso.so.1 =>  (0x00007f40afc0f000)
  #       linux-vdso.so.1 (0x00007f76b9377000)
  #       lib foo.so => /tmp/sharedlib/lib foo.so (0x00007f76b9367000)
  #       libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f76b9157000)
  #       /lib64/ld-linux-x86-64.so.2 (0x00007f76b9379000)
  #
  # The lines that do not have a => should be skipped.
  # The dynamic linker should always be copied.
  # The lines that have a => could contain a space, but we copy whatever is on
  # the right side of the =>, removing the load address.
  shared_libraries = [SharedLibrary(name="ld.so", path=_LD_PATH)]
  for lib_name, lib_path in re.findall(r"(\S+) => .*?(\S+) \(", output):
    lib_path = pathlib.Path(lib_path)
    shared_libraries.append(SharedLibrary(name=lib_name, path=lib_path))

  return shared_libraries


def get_shared_libraries(
    binary_path: os.PathLike[str],
) -> Sequence[SharedLibrary]:
  """Copies the shared libraries to the shared directory."""
  env = os.environ.copy()
  env["LD_TRACE_LOADED_OBJECTS"] = "1"
  env["LD_BIND_NOW"] = "1"

  result = subprocess.run(
      [_LD_PATH, binary_path],
      capture_output=True,
      env=env,
      check=True,
  )

  return _parse_ld_trace_output(result.stdout.decode())
