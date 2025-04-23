#!/usr/bin/env python3
# Copyright 2025 Google LLC
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
import os
import dataclasses
import hashlib
import io
import json
import logging
import shutil
import subprocess
import sqlite3
import tarfile
import tempfile

from pathlib import Path
from typing import Any, Sequence, Union, Iterator

ARCHIVE_VERSION = 1


INDEX_DB_NAME = "db.sqlite"

PROJECT = Path(os.environ['PROJECT_NAME'])
SNAPSHOT_DIR = Path('/snapshot')
SRC = Path(os.getenv('SRC'))


def set_env_vars():
  os.environ['SANITIZER'] = os.environ['FUZZING_ENGINE'] = 'none'
  os.environ['LIB_FUZZING_ENGINE'] = '/usr/lib/libFuzzingEngine.a'
  os.environ['FUZZING_LANGUAGE'] = 'c++'
  os.environ['CXX'] = '/opt/indexer/clang++'
  os.environ['CC'] = '/opt/indexer/clang'


@dataclasses.dataclass(slots=True)
class BinaryMetadata:
  name: str
  binary_path: Path
  binary_args: str
  compile_commands: list[dict[str, Any]]


@dataclasses.dataclass(frozen=True)
class Manifest:
  name: str
  uuid: str
  binary_name: str
  binary_args: str
  version: int
  is_oss_fuzz: bool = False


def save_build(
  manifest: Manifest,
  *,
  source_dir: Path,
  build_dir: Path,
  index_dir: Path,
  archive_path: Path,
  overwrite: bool = False,
) -> None:
  """Saves a build archive."""
  with tempfile.NamedTemporaryFile() as tmp:
    mode = "w:gz" if archive_path.suffix.endswith("gz") else "w"
    with tarfile.open(tmp.name, mode) as tar:
      def _save_dir(path: Path, prefix: str):
        assert prefix.endswith("/")
        for root, _, files in os.walk(path):
          for file in files:
            file = Path(root, file)
            if (
                os.path.islink(str(file))
                and Path(os.readlink(str(file))).is_absolute()
            ):
              logging.warning("Adding absolute path to the tarball: %s", file)

            tar.add(
                str(file),
                arcname=prefix + str(file.relative_to(path)),
            )

      _add_string_to_tar(
        tar,
        "manifest.json",
        json.dumps(
          dataclasses.asdict(manifest),
          indent=2,
        ),
      )

      _save_dir(source_dir, "src/")
      _save_dir(build_dir, "obj/")
      _save_dir(index_dir, "idx/")
    # Warning, we overwrite here when default behavior used to be false.
    shutil.copyfile(tmp.name, archive_path)


def _add_string_to_tar(tar: tarfile.TarFile, name: str, data: str) -> None:
  data = io.BytesIO(data.encode("utf-8"))

  tar_info = tarfile.TarInfo(name)
  tar_info.size = len(data.getvalue())

  tar.addfile(tarinfo=tar_info, fileobj=data)


def enumerate_build_targets(
    root_path: Path,
) -> Sequence[BinaryMetadata]:
  """Enumerates the build targets in the project."""
  logging.info("enumerate_build_targets")
  linker_json_paths = list(
    (root_path / 'out' / 'cdb').glob('*_linker_commands.json'))

  targets = []
  logging.info('Found %i linker JSON files.', len(linker_json_paths))
  for linker_json_path in linker_json_paths:
    with linker_json_path.open('rt') as f:
      data = json.load(f)
      # TODO(unassigned): Some projects may move build files around, so being
      # more careful about the binary path and checking the build id should
      # improve the success rate.
      binary_path = Path(data['output'])
      name = binary_path.name
      binary_args = '<input_file>'
      compile_commands = data['compile_commands']

      if binary_path.is_relative_to('/out/'):
        binary_path = Path('./build', binary_path.relative_to('/out/'))

      targets.append(
        BinaryMetadata(
          name=name,
          binary_path=binary_path,
          binary_args=binary_args,
          compile_commands=compile_commands,
        )
      )

  return targets

def short_file_hash(files: Path | Sequence[Path]) -> str:
  return sha256(files)[:16]


def file_digest(file_handle, hash_obj):
  block_sz = 65536
  while True:
    chunk = file_handle.read(block_sz)
    if not chunk:
      break
    hash_obj.update(chunk)


def sha256(files: Union[Path, Sequence[Path]]) -> str:
  """Compute the sha256 of a file or sequence of files.

  Args:
    files: The file or files to hash.

  Returns:
    Hex digest.
  """
  if isinstance(files, Path):
    files = [files]
  hash_value = hashlib.sha256()
  for file in sorted(files):
    with file.open('rb') as f:
      while True:
        chunk = f.read(8192)  # Reading in 8KB chunks.
        if not chunk:
          break
        hash_value.update(chunk)
  return hash_value.hexdigest()


def copy_fuzzing_engine():
  fuzzing_engine_dir = SRC / PROJECT
  if not fuzzing_engine_dir.exists():
    fuzzing_engine_dir = SRC / 'fuzzing_engine'
    fuzzing_engine_dir.mkdir()

  shutil.copy('/opt/indexer/fuzzing_engine.cc', fuzzing_engine_dir)
  return fuzzing_engine_dir


def build_project():
  set_env_vars()
  existing_cflags = os.environ.get('CFLAGS', '')
  extra_flags = (
    '-fno-omit-frame-pointer '
    '-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION '
    '-O0 -glldb '
    '-fsanitize=address '
    '-Wno-invalid-offsetof '
    '-fsanitize-coverage=bb,no-prune,trace-pc-guard '
    '-gen-cdb-fragment-path /out/cdb '
    '-Qunused-arguments '
    '-lc++abi '
    '-isystem /usr/local/lib/clang/18 '
    '-resource-dir /usr/local/lib/clang/18 '
  )
  os.environ['CFLAGS'] = f'{existing_cflags} {extra_flags}'.strip()

  fuzzing_engine_path = copy_fuzzing_engine()

  build_fuzzing_engine_command = [
    '/opt/indexer/clang++',
    '-c',
    '-Wall',
    '-Wextra',
    '-pedantic',
    '-std=c++20',
    '-glldb',
    '-O0',
    fuzzing_engine_path / 'fuzzing_engine.cc',
    '-o',
    '/out/fuzzing_engine.o',
    '-gen-cdb-fragment-path',
    '/out/cdb',
    '-Qunused-arguments',
    '-isystem',
    '/usr/local/lib/clang/18',
    '-I', '/usr/lib/gcc/x86_64-linux-gnu/9/../../../../include/c++/9',
    '-I', '/usr/lib/gcc/x86_64-linux-gnu/9/../../../../include/x86_64-linux-gnu/c++/9',
    '-I', '/usr/lib/gcc/x86_64-linux-gnu/9/../../../../include/c++/9/backward',
    '-I', '/usr/local/lib/clang/18/include',
    '-I', '/usr/local/include',
    '-I', '/usr/include/x86_64-linux-gnu',
    '-I', '/usr/include',
  ]
  subprocess.run(build_fuzzing_engine_command, check=True, cwd='/opt/indexer')
  ar_cmd = [
      'ar',
      'rcs',
      '/opt/indexer/fuzzing_engine.a',
      '/out/fuzzing_engine.o'
  ]
  subprocess.run(ar_cmd, check=True)
  lib_fuzzing_engine = '/usr/lib/libFuzzingEngine.a'
  if os.path.exists(lib_fuzzing_engine):
    os.remove(lib_fuzzing_engine)
  os.symlink('/opt/indexer/fuzzing_engine.a', lib_fuzzing_engine)
  subprocess.run(['/usr/local/bin/compile'], check=True)


def test_target(
    target: BinaryMetadata,
    root_dir: Path,
) -> bool:
  """Tests a single target."""
  target_path = root_dir / "out" / target.name
  result = subprocess.run([str(target_path)], stderr=subprocess.PIPE)
  expected_error = f"Usage: {target_path} <input_file>\n"
  if result.stderr.decode() != expected_error or result.returncode != 1:
    logging.error(
      "Target %s failed to run: %s",
      target_path,
      result.stderr.decode(),
    )
    return False
  return True

def archive_target(
    target: BinaryMetadata,
    root_dir: Path,
) -> Path:
  """Archives a single target in the project using the exported rootfs."""
  logging.info("archive_target %s", target.name)

  build_dir = root_dir / "out"
  source_dir = root_dir / "src"

  with (build_dir / "compile_commands.json").open("wt") as f:
    json.dump(target.compile_commands, f, indent=2)

  # TODO(unassigned): This is a hack. Ideally we need to get the commit hash
  # for the project, or something like that, but this will do for now.
  target_hash = short_file_hash((build_dir / target.name))

  name = f"{PROJECT}.{target.name}"
  uuid = f"{PROJECT}.{target.name}.{target_hash}"


  with tempfile.TemporaryDirectory(prefix="index_") as index_tmp_dir:
    index_dir = Path(index_tmp_dir)
    build_dir = root_dir / "out"

    index_db_path = os.path.join(index_tmp_dir, INDEX_DB_NAME)
    cmd = ['/opt/indexer/indexer', '--build_dir', build_dir, '--index_path',
           index_db_path, '--source_dir', os.environ['SRC']]
    result = subprocess.run(cmd, check=True)
    if result.returncode != 0:
      raise Exception(
        "Running indexer failed\n"
        f"stdout:\n```\n{result.stdout.decode()}\n```\n"
        f"stderr:\n```\n{result.stderr.decode()}\n```\n"
      )


    index_dir = Path(index_tmp_dir)
    relative_root = index_dir / "relative"
    absolute_root = index_dir / "absolute"
    for file in get_index_files(index_db_path):
      if not file:
        continue

      if file.startswith("<"):
        # builtins, we can't collect source for these.
        continue

      file_path = Path(file)
      if file_path.is_absolute():
        if file_path.is_relative_to("/"):
          index_path = absolute_root / file_path.relative_to("/")
        elif clang_include_root and file_path.is_relative_to(clang_include_root):
          index_path = absolute_root / file_path.relative_to(clang_include_root)
        else:
          raise FileNotFoundError(
            f"Absolute file path {file_path} is not in the sysroot or clang "
            " include directory."
          )
      else:
        file_path = source_dir / file_path
        index_path = relative_root / file_path.relative_to(source_dir)

      if not file_path.is_dir():
        index_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(file_path, index_path)

    archive_path = SNAPSHOT_DIR / f"{uuid}.tar"

    save_build(
      Manifest(
        name=name,
        uuid=uuid,
        binary_name=target.name,
        binary_args=target.binary_args,
        version=ARCHIVE_VERSION,
        is_oss_fuzz=False,
      ),
      source_dir=source_dir,
      build_dir=build_dir,
      index_dir=index_dir,
      archive_path=archive_path,
    )

    logging.info("Wrote archive to: %s", archive_path)

  return archive_path


def index():
  root = Path('/')
  targets = enumerate_build_targets(root)
  for target in targets:
    try:
      # TODO(metzman): Figure out if this is a good idea, it makes some things
      # pass that should but causes some things to pass that shouldn't.
      if not test_target(target, root):
        continue
    except Exception as e:
      print(f'Error: {e}')
      continue
    archive_target(target, root)



def get_index_files(index_db_path) -> Iterator[str]:
    conn = sqlite3.connect(index_db_path)
    cursor = conn.cursor()

    query = f"""
        SELECT DISTINCT dirname, basename
        FROM location
    """
    cursor.execute(query)
    for dirname, basename in cursor.fetchall():
        yield os.path.join(dirname, basename)

    conn.close()


def main():
  for directory in ['aflplusplus', 'fuzztest', 'honggfuzz', 'libfuzzer']:
    path = os.path.join(os.environ['SRC'], directory)
    shutil.rmtree(path, ignore_errors=True)
  # Initially, we put snapshots directly in /out. This caused a bug where each
  # snapshot was added to the next because they contain the contents of /out.
  SNAPSHOT_DIR.mkdir(exist_ok=True)
  build_project()
  index()
  for snapshot in SNAPSHOT_DIR.iterdir():
    shutil.move(str(snapshot), '/out')


if __name__ == '__main__':
  main()
