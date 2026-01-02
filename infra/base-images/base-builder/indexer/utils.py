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

from collections.abc import Mapping, Sequence
import dataclasses
import os
import pathlib
import re
import subprocess
from typing import Final, Protocol

from absl import logging

from google3.pyglib import gfile
import pathlib


LD_BINARY_PATH_X86_64: Final[pathlib.Path] = (
    pathlib.Path("/lib64/ld-linux-x86-64.so.2")
)

LD_BINARY_PATH_X86: Final[pathlib.Path] = pathlib.Path("/lib32/ld-linux.so.2")


@dataclasses.dataclass(frozen=True)
class SharedLibrary:
  """A shared library with its name and path."""

  name: str
  path: pathlib.Path


def _parse_ld_trace_output(
    output: str, ld_binary_path: pathlib.Path
) -> Sequence[SharedLibrary]:
  """Parses the output of `LD_TRACE_LOADED_OBJECTS=1 ld.so`."""
  if "statically linked" in output:
    return []

  # Example output:
  #       linux-vdso.so.1 =>  (0x00007f40afc0f000)
  #       linux-vdso.so.1 (0x00007f76b9377000)
  #       lib foo.so => /tmp/sharedlib/lib foo.so (0x00007f76b9367000)
  #       libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f76b9157000)
  #       /lib64/ld-linux-x86-64.so.2 (0x00007f76b9379000)
  # The last line can also be:
  #       /grte/lib64/lib64/ld-linux-x86-64.so.2 => /lib64/ld-linux-x86-64.so.2
  # (0x00007f76b9379000)
  #
  # The lines that do not have a => should be skipped.
  # The dynamic linker should always be copied AND have its executable bit set.
  # The lines that have a => could contain a space, but we copy whatever is on
  # the right side of the =>, removing the load address.
  shared_libraries = [
      SharedLibrary(name=ld_binary_path.name, path=ld_binary_path)
  ]
  for lib_name, lib_path in re.findall(r"(\S+) => .*?(\S+) \(", output):
    lib_path = pathlib.Path(lib_path)
    if lib_path == ld_binary_path:
      continue
    shared_libraries.append(SharedLibrary(name=lib_name, path=lib_path))

  return shared_libraries


class CommandRunner(Protocol):
  """Runs `command` with environment `env` and returns its stdout."""

  def __call__(
      self,
      command: Sequence[str | os.PathLike[str]],
      env: Mapping[str, str] | None = None,
  ) -> bytes:
    pass


def run_subprocess(
    command: Sequence[str | os.PathLike[str]],
    env: Mapping[str, str] | None = None,
) -> bytes:
  return subprocess.run(
      command,
      capture_output=True,
      env=env,
      check=True,
  ).stdout


def get_shared_libraries(
    binary_path: os.PathLike[str],
    command_runner: CommandRunner = run_subprocess,
    ld_binary_path: pathlib.Path = LD_BINARY_PATH_X86_64,
) -> Sequence[SharedLibrary]:
  """Enumerates the shared libraries required by the given binary."""
  env = os.environ | {
      "LD_TRACE_LOADED_OBJECTS": "1",
      "LD_BIND_NOW": "1",
  }
  stdout_bytes = command_runner([ld_binary_path, binary_path], env=env)
  return _parse_ld_trace_output(stdout_bytes.decode(), ld_binary_path)


def copy_shared_libraries(
    libraries: Sequence[SharedLibrary], dst_path: pathlib.Path
) -> None:
  """Copies the shared libraries to the shared directory."""
  for lib in libraries:
    try:
      logging.info("Copying %s => %s", lib.name, lib.path)
      gfile.Copy(lib.path, dst_path / lib.path.name, overwrite=True, mode=0o755)
    except gfile.GOSError:
      logging.exception("Could not copy %s to %s", lib.path, dst_path)
      raise


def patch_binary_rpath_and_interpreter(
    binary_path: os.PathLike[str],
    lib_mount_path: pathlib.Path,
    ld_binary_path: pathlib.Path = LD_BINARY_PATH_X86_64,
):
  """Patches the binary rpath and interpreter."""
  subprocess.run(
      [
          "patchelf",
          "--set-rpath",
          lib_mount_path.as_posix(),
          "--force-rpath",
          binary_path,
      ],
      check=True,
  )

  subprocess.run(
      [
          "patchelf",
          "--set-interpreter",
          (lib_mount_path / ld_binary_path.name).as_posix(),
          binary_path,
      ],
      check=True,
  )


def get_library_mount_path(binary_id: str) -> pathlib.Path:
  return pathlib.Path("/tmp") / (binary_id + "_lib")


def report_progress(stage: str, is_done: bool = False) -> None:
  """Reports progress of a stage of the snapshotting process."""
  logging.info("%s%s", stage, "..." if not is_done else "")
