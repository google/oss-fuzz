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
"""Classes and tools to build an indexer snapshot according to the spec.

A snapshot is a tarball containing the following:
- source files
- build artifacts (e.g. object files, shared libraries)
- indexer artifacts (e.g. clang command lines, symbol files)
- the manifest.json file, according to the Manifest class below.
"""

import dataclasses
import enum
import io
import json
import logging
import os
import pathlib
import shutil
import tarfile
import tempfile
from typing import Any, Callable

import pathlib

# Source directory.
SRC_DIR = pathlib.Path("src")
# Object directory.
OBJ_DIR = pathlib.Path("obj")
# Directory for indexer data.
INDEX_DIR = pathlib.Path("idx")
# Library directory, where shared libraries are copied - inside obj.
LIB_DIR = OBJ_DIR / "lib"
# Manifest location
MANIFEST_PATH = pathlib.Path("manifest.json")
# The current version of the build archive format.
ARCHIVE_VERSION = 2
# Where archive version 1 expects the lib directory to be mounted.
_LIB_MOUNT_PATH_V1 = pathlib.Path("/ossfuzzlib")
# Versions of the build archive format that we currently support.
_SUPPORTED_ARCHIVE_VERSIONS = frozenset([1, 2])


class RepositoryType(enum.Enum):
  """The type of repository."""

  GIT = enum.auto()
  SVN = enum.auto()
  HG = enum.auto()


@dataclasses.dataclass(frozen=True)
class SourceRef:
  """The reference to a source code repository.

  Attributes:
    type: The type of repository.
    url: The URL of the repository.
    rev: The revision of the repository.
  """

  type: str
  url: str
  rev: str

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> 'SourceRef':
    """Creates a SourceRef object from a deserialized dict."""
    return SourceRef(url=data["url"], rev=data["rev"], type=data["type"])


@dataclasses.dataclass(frozen=True)
class Reproducibility:
  """A report of how reproducible a known bug is."""

  # How many of the trials succeeded in reproducing the behavior?
  success_count: int = 0

  # How many reproduction trials were attempted?
  trial_count: int = 0

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> 'Reproducibility':
    """Creates a Reproducibility object from a deserialized dict."""
    return Reproducibility(
        success_count=data["success_count"],
        trial_count=data["trial_count"],
    )


@dataclasses.dataclass(frozen=True)
class Manifest:
  """Contains general meta-information about the snapshot."""

  name: str
  uuid: str
  binary_name: str
  binary_args: str

  # The path prefix of the actual build directory (e.g., a temporary file in
  # the build host). It's used during replay to remove noisy source-file
  # prefixes from reports.
  source_dir_prefix: str = ""

  # The reproducibility information about the bug in this snapshot.
  reproducibility: Reproducibility | None = None

  # Example source map:
  # {
  #   "/src/hunspell": {
  #     "type": "git",
  #     "url": "https://github.com/hunspell/hunspell.git",
  #     "rev": "a9b7270c1c2832312cfb20c3d1cf5c5080bf221b"
  #   }
  # }
  source_map: dict[pathlib.Path, SourceRef] | None = None
  lib_mount_path: pathlib.Path | None = None
  version: int = ARCHIVE_VERSION

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> 'Manifest':
    """Creates a Manifest object from a deserialized dict."""
    if data["version"] == 1:
      lib_mount_path = _LIB_MOUNT_PATH_V1
    else:
      lib_mount_path = _get_mapped(data, "lib_mount_path", pathlib.Path)
    return Manifest(
        name=data["name"],
        uuid=data["uuid"],
        binary_name=data["binary_name"],
        binary_args=data["binary_args"],
        lib_mount_path=lib_mount_path,
        source_map=_get_mapped(data, "source_map", source_map_from_dict),
        source_dir_prefix=data.get("source_dir_prefix"),
        reproducibility=_get_mapped(data, "reproducibility",
                                    Reproducibility.from_dict),
        version=data["version"],
    )

  def to_dict(self) -> dict[str, Any]:
    """Converts a Manifest object to a serializable dict."""
    data = dataclasses.asdict(self)
    data["lib_mount_path"] = _get_mapped(data, "lib_mount_path",
                                         lambda x: x.as_posix())
    data["source_map"] = _get_mapped(data, "source_map", source_map_to_dict)
    return data

  def validate(self) -> None:
    """Validates the manifest with some simple checks.

    Raises:
      RuntimeError: If the manifest is invalid.
    """
    if self.version not in _SUPPORTED_ARCHIVE_VERSIONS:
      raise RuntimeError(
          "Build archive with version {self.version} is not supported."
          f" Supported versions are {_SUPPORTED_ARCHIVE_VERSIONS}.")
    if self.version == 1 and _LIB_MOUNT_PATH_V1 != self.lib_mount_path:
      raise RuntimeError(
          "Build archive with version 1 has an alternative lib_mount_path set"
          f" ({self.lib_mount_path}). This is not a valid archive.")
    if not self.name or not self.uuid or not self.binary_name:
      raise RuntimeError(
          "Attempting to load a manifest with missing fields. Expected all"
          " fields to be set, but got {self}")
    if self.source_map is not None:
      for _, ref in self.source_map.items():
        if not ref.url:
          raise RuntimeError(
              "Attempting to load a manifest with a source map entry with an"
              " empty URL. Source map entry: {ref}")

  def save_build(
      self,
      *,
      source_dir: pathlib.PurePath,
      build_dir: pathlib.PurePath,
      index_dir: pathlib.PurePath,
      archive_path: pathlib.PurePath,
      out_dir: pathlib.PurePath = pathlib.Path("/out"),
      overwrite: bool = True,
  ) -> None:
    """Saves a build archive with this Manifest."""
    self.validate()
    with tempfile.NamedTemporaryFile() as tmp:
      mode = "w:gz" if archive_path.suffix.endswith("gz") else "w"
      with tarfile.open(tmp.name, mode) as tar:

        def _save_dir(
            path: pathlib.PurePath,
            prefix: pathlib.Path,
            exclude_build_artifacts: bool = False,
            only_include_target: str | None = None,
        ):
          prefix = prefix.as_posix() + "/"
          for root, _, files in os.walk(path):
            for file in files:
              if file.endswith("_seed_corpus.zip"):
                # Don't copy over the seed corpus -- it's not necessary.
                continue

              file = pathlib.Path(root, file)
              if exclude_build_artifacts and _is_elf(file):
                continue

              if only_include_target and _is_elf(file):
                # Skip ELF files that aren't the relevant target (unless it's a
                # shared library).
                if (file.name != only_include_target and
                    ".so" not in file.name and
                    not file.absolute().is_relative_to(out_dir / "lib")):
                  continue

              tar.add(
                  # Don't try to replicate symlinks in the tarfile, because they
                  # can lead to various issues (e.g. absolute symlinks).
                  file.resolve().as_posix(),
                  arcname=prefix + str(file.relative_to(path)),
              )

        _add_string_to_tar(
            tar,
            MANIFEST_PATH.as_posix(),
            json.dumps(
                self.to_dict(),
                indent=2,
            ),
        )

        _save_dir(source_dir, SRC_DIR, exclude_build_artifacts=True)
        # Only include the relevant target for the snapshot, to save on disk
        # space.
        _save_dir(build_dir, OBJ_DIR, only_include_target=self.binary_name)
        _save_dir(index_dir, INDEX_DIR)

      if os.path.exists(archive_path) and not overwrite:
        logging.warning("Skipping existing archive %s", archive_path)
      else:
        shutil.copyfile(tmp.name, archive_path)


def _get_mapped(data: dict[str, Any], key: str,
                mapper: Callable[[Any], Any]) -> Any | None:
  """Get a value from a dict and apply a mapper to it, if it's not None."""
  value = data.get(key)
  if value is None:
    return None
  return mapper(value)


def source_map_from_dict(data: dict[str, Any]) -> dict[pathlib.Path, SourceRef]:
  """Converts a path: obj dict to a dictionary of SourceRef objects."""
  return {pathlib.Path(x): SourceRef.from_dict(y) for x, y in data.items()}


def source_map_to_dict(x: dict[pathlib.Path, SourceRef],) -> dict[str, Any]:
  """Converts a dictionary of SourceRef objects to a string: obj dict."""
  return {k.as_posix(): v for k, v in x.items()}


def _add_string_to_tar(tar: tarfile.TarFile, name: str, data: str) -> None:
  bytesio = io.BytesIO(data.encode("utf-8"))

  tar_info = tarfile.TarInfo(name)
  tar_info.size = len(bytesio.getvalue())

  tar.addfile(tarinfo=tar_info, fileobj=bytesio)


def _is_elf(path: pathlib.PurePath) -> bool:
  """Checks if a file is an ELF file."""
  try:
    with open(path, "rb") as f:
      return f.read(4) == b"\x7fELF"
  except OSError:
    # Can happen if the file is a symlink, etc.
    return False
