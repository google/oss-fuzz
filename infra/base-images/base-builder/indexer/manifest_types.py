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

import manifest_constants
import pathlib


SRC_DIR = manifest_constants.SRC_DIR
OBJ_DIR = manifest_constants.OBJ_DIR
INDEX_DIR = manifest_constants.INDEX_DIR
INDEX_DB = manifest_constants.INDEX_DB
LIB_DIR = manifest_constants.LIB_DIR
MANIFEST_PATH = manifest_constants.MANIFEST_PATH
LIB_MOUNT_PATH_V1 = manifest_constants.LIB_MOUNT_PATH_V1

INPUT_FILE = manifest_constants.INPUT_FILE
OUTPUT_FILE = manifest_constants.OUTPUT_FILE
DYNAMIC_ARGS = manifest_constants.DYNAMIC_ARGS

# Min archive version we currently support.
_MIN_SUPPORTED_ARCHIVE_VERSION = 1
# The current version of the build archive format.
ARCHIVE_VERSION = 5
# OSS-Fuzz $OUT dir.
OUT = pathlib.Path(os.getenv("OUT", "/out"))
# OSS-Fuzz coverage info.
_COVERAGE_INFO_URL = (
    "https://storage.googleapis.com/oss-fuzz-coverage/"
    f"latest_report_info/{os.getenv('PROJECT_NAME')}.json"
)


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
    return SourceRef(
        url=data["url"], rev=data["rev"], type=RepositoryType(data["type"])
    )


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


class BinaryConfigKind(enum.StrEnum):
  """The kind of binary configurations."""

  OSS_FUZZ = enum.auto()
  BINARY = enum.auto()

  def validate_in(self, options: list[Self]):
    if self not in options:
      raise ValueError(
          f"Expected one of the following binary config kinds: {options}, "
          f"but got {self}"
      )


@dataclasses.dataclass(frozen=True, kw_only=True)
class BinaryConfig:
  """Base binary configuration.

  Attributes:
    kind: The kind of binary configuration.
    binary_name: The name of the executable file.
  """

  kind: BinaryConfigKind

  binary_name: str

  @property
  def uses_stdin(self) -> bool:
    """Whether the binary uses stdin."""
    del self
    return False

  @classmethod
  def from_dict(cls, config_dict: Mapping[str, Any]) -> Self:
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

  def to_dict(self) -> dict[str, Any]:
    """Converts a BinaryConfig object to a serializable dict."""
    return dataclasses.asdict(self)


class HarnessKind(enum.StrEnum):
  """The target/harness kind."""

  LIBFUZZER = enum.auto()
  BINARY = enum.auto()
  # The target is a JavaScript shell that consumes JavaScript code.
  JS = enum.auto()


@dataclasses.dataclass(frozen=True, kw_only=True)
class CommandLineBinaryConfig(BinaryConfig):
  """Configuration for a command-line userspace binary."""

  binary_args: list[str]
  # Additional environment variables to pass to the binary. They will overwrite
  # any existing environment variables with the same name.
  # Input replacement works on these variables as well.
  binary_env: dict[str, str] = dataclasses.field(default_factory=dict)
  harness_kind: HarnessKind
  # Whether to filter the compile commands to only include object files that
  # are directly linked into the target binary. Should usually be true but
  # some targets like V8 require this to be false, see b/433718862.
  filter_compile_commands: bool = True

  @property
  def uses_stdin(self) -> bool:
    """Whether the binary uses stdin."""
    return manifest_constants.INPUT_FILE not in self.binary_args

  @classmethod
  def from_dict(cls, config_dict: Mapping[str, Any]) -> Self:
    """Deserializes the `CommandLineBinaryConfig` from a dict."""
    kind = BinaryConfigKind(config_dict["kind"])
    kind.validate_in([BinaryConfigKind.OSS_FUZZ, BinaryConfigKind.BINARY])
    # Default to "binary" for backwards compatibility.
    harness_kind = HarnessKind(
        config_dict.get("harness_kind", HarnessKind.BINARY)
    )
    return CommandLineBinaryConfig(
        kind=kind,
        harness_kind=harness_kind,
        binary_name=config_dict["binary_name"],
        binary_args=config_dict["binary_args"],
        binary_env=config_dict.get("binary_env", {}),
        filter_compile_commands=config_dict.get(
            "filter_compile_commands", True
        ),
    )





def _get_sqlite_db_user_version(sqlite_db_path: pathlib.Path) -> int:
  """Retrieves `PRAGMA user_version;` value without connecting to the database."""
  with sqlite_db_path.open("rb") as stream:
    # https://www.sqlite.org/pragma.html#pragma_user_version - a big-endian
    # 32-bit number at offset 60 of the database header.
    too_small_error = ValueError(
        f"The file '{sqlite_db_path}' is too small for an SQLite database."
    )
    try:
      stream.seek(60)
    except OSError as e:
      raise too_small_error from e

    version_bytes = stream.read(4)
    if len(version_bytes) < 4:
      raise too_small_error

    return int.from_bytes(version_bytes, byteorder="big")


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

  # Version of the index database schema.
  index_db_version: int | None = None

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> Self:
    """Creates a Manifest object from a deserialized dict."""
    if data["version"] == 1:
      lib_mount_path = LIB_MOUNT_PATH_V1
    else:
      lib_mount_path = _get_mapped(data, "lib_mount_path", pathlib.Path)
    if data["version"] < 3:
      if not isinstance(data.get("binary_args"), str):
        raise RuntimeError(
            "binary_args must be a string in version 1 and 2, but got"
            f" {type(data.get('binary_args'))}"
        )
      binary_args = _get_mapped(data, "binary_args", shlex.split)
    else:
      binary_args = data.get("binary_args")
    if data["version"] < 4:
      binary_config = CommandLineBinaryConfig(
          kind=BinaryConfigKind.BINARY,
          binary_name=data["binary_name"],
          binary_args=binary_args or [],
          harness_kind=HarnessKind.BINARY,
          binary_env={},
      )
    else:
      binary_config = _get_mapped(data, "binary_config", BinaryConfig.from_dict)

    version = data["version"]
    if _MIN_SUPPORTED_ARCHIVE_VERSION <= version <= ARCHIVE_VERSION:
      # Upgrade archive version - we have upgraded all necessary fields.
      version = ARCHIVE_VERSION
    else:
      logging.warning(
          "Unsupported manifest version %s detected. Not upgrading.", version
      )
    return Manifest(
        version=version,
        index_db_version=data.get("index_db_version"),
        name=data["name"],
        uuid=data["uuid"],
        lib_mount_path=lib_mount_path,
        source_map=_get_mapped(data, "source_map", source_map_from_dict),
        source_dir_prefix=data.get("source_dir_prefix"),
        reproducibility=_get_mapped(
            data, "reproducibility", Reproducibility.from_dict
        ),
        binary_config=binary_config,
    )

  def to_dict(self) -> dict[str, Any]:
    """Converts a Manifest object to a serializable dict."""
    data = dataclasses.asdict(self)

    data["binary_config"] = self.binary_config.to_dict()
    data["lib_mount_path"] = _get_mapped(
        data, "lib_mount_path", lambda x: x.as_posix()
    )
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
          f" least {_MIN_SUPPORTED_ARCHIVE_VERSION}."
      )
    if self.version > ARCHIVE_VERSION:
      raise RuntimeError(
          f"Build archive version too high: {self.version}. Only supporting"
          f" up to {ARCHIVE_VERSION}."
      )
    if self.version == 1 and LIB_MOUNT_PATH_V1 != self.lib_mount_path:
      raise RuntimeError(
          "Build archive with version 1 has an alternative lib_mount_path set"
          f" ({self.lib_mount_path}). This is not a valid archive."
      )
    if not self.name or not self.uuid or not self.binary_config:
      raise RuntimeError(
          "Attempting to load a manifest with missing fields. Expected all"
          " fields to be set, but got {self}"
      )
    if self.source_map is not None:
      for _, ref in self.source_map.items():
        if not ref.url:
          raise RuntimeError(
              "Attempting to load a manifest with a source map entry with an"
              " empty URL. Source map entry: {ref}"
          )
    # check very simple basic types.
    for k, v in self.__annotations__.items():
      if not isinstance(v, type):
        continue
      if not isinstance(getattr(self, k), v):
        raise RuntimeError(
            f"Type mismatch for field {k}: expected {v}, got"
            f" {type(getattr(self, k))}"
        )
    # We updated from string to list in version 3, make sure this propagated.
    binary_config = self.binary_config
    if hasattr(binary_config, "binary_args"):
      if not isinstance(binary_config.binary_args, list):
        raise RuntimeError(
            "Type mismatch for field binary_config.binary_args: expected list,"
            f"got {type(binary_config.binary_args)}"
        )

  def save_build(
      self,
      *,
      source_dir: pathlib.PurePath | None,
      build_dir: pathlib.PurePath,
      index_dir: pathlib.PurePath,
      archive_path: pathlib.PurePath,
      out_dir: pathlib.PurePath = pathlib.Path("/out"),
      overwrite: bool = True,
  ) -> Self:
    """Saves a build archive with this Manifest."""
    if os.path.exists(archive_path) and not overwrite:
      raise FileExistsError(f"Not overwriting existing archive {archive_path}")

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

              if "/.git/" in root or root.endswith("/.git"):
                # Skip the .git directory -- it can be large.
                continue

              file = pathlib.Path(root, file)
              if exclude_build_artifacts and _is_elf(file):
                continue

              if only_include_target and _is_elf(file):
                # Skip ELF files that aren't the relevant target (unless it's a
                # shared library).
                if (
                    file.name != only_include_target
                    and ".so" not in file.name
                    and not file.absolute().is_relative_to(out_dir / "lib")
                ):
                  continue

              tar.add(
                  # Don't try to replicate symlinks in the tarfile, because they
                  # can lead to various issues (e.g. absolute symlinks).
                  file.resolve().as_posix(),
                  arcname=prefix + str(file.relative_to(path)),
              )

        dumped_self = self
        if self.index_db_version is None:
          index_db_version = _get_sqlite_db_user_version(
              pathlib.Path(index_dir) / INDEX_DB
          )
          dumped_self = dataclasses.replace(
              self, index_db_version=index_db_version
          )

        # Make sure the manifest is the first file in the archive to avoid
        # seeking when we only need the manifest.
        _add_string_to_tar(
            tar,
            MANIFEST_PATH.as_posix(),
            json.dumps(
                dumped_self.to_dict(),
                indent=2,
            ),
        )

        # Make sure the index databases (the only files directly in `INDEX_DIR`)
        # are early in the archive for the same reason.
        _save_dir(index_dir, INDEX_DIR)

        if source_dir:
          _save_dir(source_dir, SRC_DIR, exclude_build_artifacts=True)

        # Only include the relevant target for the snapshot, to save on disk
        # space.
        _save_dir(
            build_dir,
            OBJ_DIR,
            only_include_target=self.binary_config.binary_name,
        )

        if self.binary_config.kind == BinaryConfigKind.OSS_FUZZ:
          copied_files = [tar_info.name for tar_info in tar.getmembers()]
          try:
            report_missing_source_files(
                self.binary_config.binary_name, copied_files, tar
            )
          except Exception as e:  # pylint: disable=broad-except
            logging.warning("Failed to report missing source files: %s", e)

      shutil.copyfile(tmp.name, archive_path)

      return dumped_self


def report_missing_source_files(
    binary_name: str, copied_files: list[str], tar: tarfile.TarFile
):
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
      "gs://", "https://storage.googleapis.com/"
  )

  target_url = f"{stats_url}/{target}.json"
  with urllib.request.urlopen(target_url) as resp:
    target_cov = json.load(resp)

  files = target_cov["data"][0]["files"]
  return [
      file["filename"]
      for file in files
      if file["summary"]["regions"]["covered"]
  ]


def _get_mapped(
    data: dict[str, Any], key: str, mapper: Callable[[Any], Any]
) -> Any | None:
  """Get a value from a dict and apply a mapper to it, if it's not None."""
  value = data.get(key)
  if value is None:
    return None
  return mapper(value)


def source_map_from_dict(data: dict[str, Any]) -> dict[pathlib.Path, SourceRef]:
  """Converts a path: obj dict to a dictionary of SourceRef objects."""
  return {pathlib.Path(x): SourceRef.from_dict(y) for x, y in data.items()}


def source_map_to_dict(
    x: dict[pathlib.Path, SourceRef],
) -> dict[str, Any]:
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


def parse_env(env_list: list[str]) -> dict[str, str]:
  """Helper function to parse environment variables from a list.

  Args:
    env_list: A list of environment variables in the format of "key=value".

  Returns:
    A dictionary of environment variables.

  Raises:
    ValueError: If a key is empty or invalid.
  """
  env = {}

  def assert_key_valid(key: str) -> None:
    if not key:
      raise ValueError("Environment variable key is empty.")
    # Check that the key looks like a valid environment variable name.

    if key in env:
      raise ValueError(
          f"Environment variable key {key} is defined twice. "
          f"Existing value: {env[key]}, new value: {value}."
      )

  for entry in env_list:
    if "=" not in entry:
      logging.warning(
          "Environment variable string is not in the format of 'key=value': %s",
          entry,
      )
    key, _, value = entry.partition("=")
    assert_key_valid(key)
    env[key] = value

  return env
