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
import shlex
import shutil
import tarfile
import tempfile
from typing import Any, Callable, Mapping, Self, Sequence
import urllib.request

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
# Where archive version 1 expects the lib directory to be mounted.
_LIB_MOUNT_PATH_V1 = pathlib.Path("/ossfuzzlib")
# Min archive version we currently support.
_MIN_SUPPORTED_ARCHIVE_VERSION = 1
# The current version of the build archive format.
ARCHIVE_VERSION = 4
# OSS-Fuzz $OUT dir.
OUT = pathlib.Path(os.getenv("OUT", "/out"))
# OSS-Fuzz coverage info.
_COVERAGE_INFO_URL = ("https://storage.googleapis.com/oss-fuzz-coverage/"
                      f"latest_report_info/{os.getenv('PROJECT_NAME')}.json")

# Will be replaced with the input file for target execution.
INPUT_FILE = "<input_file>"
# A file the target can write output to.
OUTPUT_FILE = "<output_file>"


class RepositoryType(enum.StrEnum):
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

  type: RepositoryType
  url: str
  rev: str

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> Self:
    """Creates a SourceRef object from a deserialized dict."""
    return SourceRef(url=data["url"],
                     rev=data["rev"],
                     type=RepositoryType(data["type"]))


@dataclasses.dataclass(frozen=True)
class Reproducibility:
  """A report of how reproducible a known bug is."""

  # How many of the trials succeeded in reproducing the behavior?
  success_count: int = 0

  # How many reproduction trials were attempted?
  trial_count: int = 0

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> Self:
    """Creates a Reproducibility object from a deserialized dict."""
    return Reproducibility(
        success_count=data["success_count"],
        trial_count=data["trial_count"],
    )


@dataclasses.dataclass(frozen=True)
class ReplacedBinaryArgs:
  """Contains the new binary args and the stdin path."""

  # The new binary args.
  binary_args: list[str] | None
  # The original stdin path.
  input_path: str
  # Whether the stdin path was replaced.
  input_replaced: bool

  def from_dict(self, data: dict[str, Any]) -> Self:
    """Creates a ReplacedBinaryArgs object from a deserialized dict."""
    return ReplacedBinaryArgs(
        binary_args=data.get("binary_args"),
        input_path=data["input_path"],
        input_replaced=data["input_replaced"],
    )


class BinaryConfigKind(enum.StrEnum):
  """The kind of binary configurations."""

  OSS_FUZZ = enum.auto()
  BINARY = enum.auto()

  def validate_in(self, options: list[Self]):
    if self not in options:
      raise ValueError(
          f"Expected one of the following binary config kinds: {options}, "
          f"but got {self}")


@dataclasses.dataclass(frozen=True, kw_only=True)
class BinaryConfig:
  """Base binary configuration.

  Attributes:
    kind: The kind of binary configuration.
    binary_args: The arguments to pass to the binary, for example
      "<input_file>".
  """

  kind: BinaryConfigKind

  @classmethod
  def from_dict(cls, config_dict: Mapping[Any, Any]) -> Self:
    """Deserializes the correct `BinaryConfig` subclass from a dict."""
    mapping = {
        BinaryConfigKind.OSS_FUZZ: CommandLineBinaryConfig,
        BinaryConfigKind.BINARY: CommandLineBinaryConfig,
    }
    kind = config_dict["kind"]
    if kind not in mapping:
      raise ValueError(f"Unknown BinaryConfigKind: {kind}")
    val = config_dict
    if isinstance(val.get("binary_args"), str):
      logging.warning(
          "BinaryConfig: binary_args is type string instead of list."
          " This is deprecated. Converting to list. Args: %s",
          val["binary_args"],
      )
      val = dict(val, binary_args=shlex.split(val["binary_args"]))
    return mapping[kind].from_dict(val)

  def to_dict(self) -> Mapping[Any, Any]:
    """Converts a BinaryConfig object to a serializable dict."""
    return dataclasses.asdict(self)


@dataclasses.dataclass(frozen=True, kw_only=True)
class CommandLineBinaryConfig(BinaryConfig):
  """Configuration for a command-line userspace binary."""

  binary_name: str
  binary_args: list[str]

  @classmethod
  def from_dict(cls, config_dict: Mapping[Any, Any]) -> Self:
    """Deserializes the `CommandLineBinaryConfig` from a dict."""
    kind = BinaryConfigKind(config_dict["kind"])
    kind.validate_in([BinaryConfigKind.OSS_FUZZ, BinaryConfigKind.BINARY])
    return CommandLineBinaryConfig(
        kind=kind,
        binary_name=config_dict["binary_name"],
        binary_args=config_dict["binary_args"],
    )


@dataclasses.dataclass(frozen=True)
class Manifest:
  """Contains general meta-information about the snapshot."""

  # The name of the target.
  name: str
  # A unique identifier for the snapshot (not necessarily a valid UUID).
  uuid: str
  # A fixed path that shared libraries stored at `./obj/lib` should be mounted
  # at before running the target.
  lib_mount_path: pathlib.Path | None

  # The binary configuration used to build the snapshot.
  binary_config: BinaryConfig

  # The path prefix of the actual build directory (e.g., a temporary file in
  # the build host). It's used during replay to remove noisy source-file
  # prefixes from reports.
  source_dir_prefix: str | None = None

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

  # Version of the manifest spec.
  version: int = ARCHIVE_VERSION

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> Self:
    """Creates a Manifest object from a deserialized dict."""
    if data["version"] == 1:
      lib_mount_path = _LIB_MOUNT_PATH_V1
    else:
      lib_mount_path = _get_mapped(data, "lib_mount_path", pathlib.Path)
    if data["version"] < 3:
      if not isinstance(data.get("binary_args"), str):
        raise RuntimeError(
            "binary_args must be a string in version 1 and 2, but got"
            f" {type(data.get('binary_args'))}")
      binary_args = _get_mapped(data, "binary_args", shlex.split)
    else:
      binary_args = data.get("binary_args")
    if data["version"] < 4:
      binary_config = CommandLineBinaryConfig(
          kind=BinaryConfigKind.BINARY,
          binary_name=data["binary_name"],
          binary_args=binary_args or [],
      )
    else:
      binary_config = _get_mapped(data, "binary_config", BinaryConfig.from_dict)

    version = data["version"]
    if _MIN_SUPPORTED_ARCHIVE_VERSION <= version <= ARCHIVE_VERSION:
      # Upgrade archive version - we have upgraded all necessary fields.
      version = ARCHIVE_VERSION
    else:
      logging.warning(
          "Unsupported manifest version %s detected. Not upgrading.", version)
    return Manifest(
        version=version,
        name=data["name"],
        uuid=data["uuid"],
        lib_mount_path=lib_mount_path,
        source_map=_get_mapped(data, "source_map", source_map_from_dict),
        source_dir_prefix=data.get("source_dir_prefix"),
        reproducibility=_get_mapped(data, "reproducibility",
                                    Reproducibility.from_dict),
        binary_config=binary_config,
    )

  def to_dict(self) -> dict[str, Any]:
    """Converts a Manifest object to a serializable dict."""
    data = dataclasses.asdict(self)

    data["binary_config"] = self.binary_config.to_dict()
    data["lib_mount_path"] = _get_mapped(data, "lib_mount_path",
                                         lambda x: x.as_posix())
    data["source_map"] = _get_mapped(data, "source_map", source_map_to_dict)

    return data

  def validate(self) -> None:
    """Validates the manifest with some simple checks.

    Raises:
      RuntimeError: If the manifest is invalid.
    """
    if self.version < _MIN_SUPPORTED_ARCHIVE_VERSION:
      raise RuntimeError(
          f"Build archive version too low: {self.version}. Supporting at"
          f" least {_MIN_SUPPORTED_ARCHIVE_VERSION}.")
    if self.version > ARCHIVE_VERSION:
      raise RuntimeError(
          f"Build archive version too high: {self.version}. Only supporting"
          f" up to {ARCHIVE_VERSION}.")
    if self.version == 1 and _LIB_MOUNT_PATH_V1 != self.lib_mount_path:
      raise RuntimeError(
          "Build archive with version 1 has an alternative lib_mount_path set"
          f" ({self.lib_mount_path}). This is not a valid archive.")
    if not self.name or not self.uuid or not self.binary_config:
      raise RuntimeError(
          "Attempting to load a manifest with missing fields. Expected all"
          " fields to be set, but got {self}")
    if self.source_map is not None:
      for _, ref in self.source_map.items():
        if not ref.url:
          raise RuntimeError(
              "Attempting to load a manifest with a source map entry with an"
              " empty URL. Source map entry: {ref}")
    # check very simple basic types.
    for k, v in self.__annotations__.items():
      if not isinstance(v, type):
        continue
      if not isinstance(getattr(self, k), v):
        raise RuntimeError(f"Type mismatch for field {k}: expected {v}, got"
                           f" {type(getattr(self, k))}")
    # We updated from string to list in version 3, make sure this propagated.
    binary_config = self.binary_config
    if hasattr(binary_config, "binary_args"):
      if not isinstance(binary_config.binary_args, list):
        raise RuntimeError(
            "Type mismatch for field binary_config.binary_args: expected list,"
            f"got {type(binary_config.binary_args)}")

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

    if not hasattr(self.binary_config, "binary_name"):
      raise RuntimeError(
          "Attempting to save a binary config type without binary_name."
          " This is not yet supported. Kind: {self.binary_config.kind}.")

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
        _save_dir(
            build_dir,
            OBJ_DIR,
            only_include_target=self.binary_config.binary_name,
        )
        _save_dir(index_dir, INDEX_DIR)
        if self.binary_config.kind == BinaryConfigKind.OSS_FUZZ:
          copied_files = [tar_info.name for tar_info in tar.getmembers()]
          try:
            report_missing_source_files(self.binary_config.binary_name,
                                        copied_files, tar)
          except Exception:  # pylint: disable=broad-except
            logging.exception("Failed to report missing source files.")

      if os.path.exists(archive_path) and not overwrite:
        logging.warning("Skipping existing archive %s", archive_path)
      else:
        shutil.copyfile(tmp.name, archive_path)


def report_missing_source_files(binary_name: str, copied_files: list[str],
                                tar: tarfile.TarFile):
  """Saves a report of missing source files to the snapshot tarball."""
  copied_files = {_get_comparable_path(file) for file in copied_files}
  covered_files = {
      _get_comparable_path(path): path
      for path in get_covered_files(binary_name)
  }
  missing = set(covered_files) - copied_files
  if not missing:
    return
  logging.info("Reporting missing files: %s", missing)
  missing_report_lines = sorted([covered_files[k] for k in missing])
  report_name = f"{binary_name}_missing_files.txt"
  tar_info = tarfile.TarInfo(name=report_name)
  missing_report = " ".join(missing_report_lines)
  missing_report_bytes = missing_report.encode("utf-8")
  tar.addfile(tarinfo=tar_info, fileobj=io.BytesIO(missing_report_bytes))
  with open(os.path.join(OUT, report_name), "w") as fp:
    fp.write(missing_report)


def _get_comparable_path(path: str) -> tuple[str, str]:
  return os.path.basename(os.path.dirname(path)), os.path.basename(path)


def get_covered_files(target: str) -> Sequence[str]:
  """Returns the files covered by fuzzing on OSS-Fuzz by the target."""
  with urllib.request.urlopen(_COVERAGE_INFO_URL) as resp:
    latest_info = json.load(resp)

  stats_url = latest_info.get("fuzzer_stats_dir").replace(
      "gs://", "https://storage.googleapis.com/")

  target_url = f"{stats_url}/{target}.json"
  with urllib.request.urlopen(target_url) as resp:
    target_cov = json.load(resp)

  files = target_cov["data"][0]["files"]
  return [
      file["filename"]
      for file in files
      if file["summary"]["regions"]["covered"]
  ]


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


def binary_args_from_placeholders(
    binary_args: list[str] | None,
    input_path: str,
    output_path: str = "/dev/null",
) -> ReplacedBinaryArgs:
  """Processes binary args.

  Args:
    binary_args: List of binary args.
    input_path: Path of the file that contains the program input bytes.
    output_path: Path of the file that contains the program output bytes
      (default to /dev/null).

  Returns:
    Processed binary args, where
      "<input_file>": replaced by input_path if applicable
      "<output_file>": replaced by /dev/null if applicable
      and a boolean indicating whether input_path was replaced.
  """
  if binary_args is None:
    return ReplacedBinaryArgs(binary_args=None,
                              input_path=input_path,
                              input_replaced=False)

  input_replaced = False

  def _replace_placeholder(arg: str) -> str:
    if INPUT_FILE in arg:
      nonlocal input_replaced
      input_replaced = True
      return arg.replace(INPUT_FILE, input_path)
    elif OUTPUT_FILE in arg:
      return arg.replace(OUTPUT_FILE, output_path)
    else:
      return arg

  return ReplacedBinaryArgs(
      binary_args=[_replace_placeholder(arg) for arg in binary_args],
      input_path=input_path,
      input_replaced=input_replaced,
  )


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
