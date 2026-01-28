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

"""This runs the actual build process to generate a snapshot."""

import argparse
import dataclasses
import hashlib
import json
import logging
import os
import pathlib
from pathlib import Path  # pylint: disable=g-importing-member
import shlex
import shutil
import stat
import subprocess
import tempfile
from typing import Any, Sequence

import manifest_types
import pathlib


PROJECT = Path(os.getenv('PROJECT_NAME', 'project')).name
SNAPSHOT_DIR = Path('/snapshot')
SRC = Path(os.getenv('SRC', '/src'))
# On OSS-Fuzz build infra, $OUT is not /out.
OUT = Path(os.getenv('OUT', '/out'))
INDEXES_PATH = Path(os.getenv('INDEXES_PATH', '/indexes'))
INCREMENTAL_CDB_PATH = Path('/incremental_cdb')
_GCC_BASE_PATH = Path('/usr/lib/gcc/x86_64-linux-gnu')

_LD_BINARY = 'ld-linux-x86-64.so.2'
_LD_PATH = Path('/lib64') / _LD_BINARY
_DEFAULT_GCC_VERSION = '9'
_LLVM_READELF_PATH = '/usr/local/bin/llvm-readelf'

DEFAULT_COVERAGE_FLAGS = '-fsanitize-coverage=bb,no-prune,trace-pc-guard'
TRACING_COVERAGE_FLAGS = '-fsanitize-coverage=func,trace-pc-guard'
DEFAULT_FUZZING_ENGINE = 'fuzzing_engine.cc'

DEFAULT_CLANG_TOOLCHAIN = '/usr/local'
_CLANG_TOOLCHAIN = Path(os.getenv('CLANG_TOOLCHAIN', DEFAULT_CLANG_TOOLCHAIN))
_TOOLCHAIN_WITH_WRAPPER = Path('/opt/toolchain')

INDEXER_DIR = Path(__file__).parent

# Some build systems isolate the compiler environment from the parent process,
# so we can't always rely on using environment variables to pass settings to the
# wrapper. Get around this by writing to a file instead.
COMPILE_SETTINGS_PATH = INDEXER_DIR / 'compile_settings.json'

CLANG_TOOLCHAIN_BINARY_PREFIXES = (
    'clang-',
    'ld',
    'lld',
    'llvm-',
)

EXTRA_CFLAGS = (
    '-fno-omit-frame-pointer '
    '-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION '
    '-O0 -glldb '
    '-fsanitize=address '
    '-Wno-invalid-offsetof '
    '{coverage_flags} '
    '-Qunused-arguments '
)


@dataclasses.dataclass(slots=True, frozen=True)
class CompileSettings:
  coverage_flags: str
  clang_toolchain: str
  clang_version: str


def read_compile_settings() -> CompileSettings:
  """Gets compile settings from file."""
  with COMPILE_SETTINGS_PATH.open('r') as f:
    settings_dict = json.load(f)

  return CompileSettings(**settings_dict)


def write_compile_settings(compile_settings: CompileSettings) -> None:
  """Writes compile settings to file."""
  with COMPILE_SETTINGS_PATH.open('w') as f:
    json.dump(dataclasses.asdict(compile_settings), f)


def set_env_vars(coverage_flags: str):
  """Set up build environment variables."""
  os.environ['SANITIZER'] = 'address'
  # Prevent ASan leak checker from running on `configure` script targets.
  # At the time of writing, this helps prevent a slowdown in `hunspell` build.
  os.environ['ASAN_OPTIONS'] = 'detect_leaks=0'
  os.environ['FUZZING_ENGINE'] = 'none'
  os.environ['LIB_FUZZING_ENGINE'] = '/usr/lib/libFuzzingEngine.a'
  os.environ['FUZZING_LANGUAGE'] = 'c++'
  os.environ['CXX'] = 'clang++'
  os.environ['CC'] = 'clang'
  os.environ['COMPILING_PROJECT'] = 'True'
  # Force users of clang to use our wrapper. This fixes e.g. libcups.
  os.environ['PATH'] = (
      f"{_TOOLCHAIN_WITH_WRAPPER / 'bin'}:{os.environ.get('PATH')}"
  )

  existing_cflags = os.environ.get('CFLAGS', '')
  extra_cflags = EXTRA_CFLAGS.format(coverage_flags=coverage_flags)
  os.environ['CFLAGS'] = f'{existing_cflags} {extra_cflags}'.strip()


def set_up_wrapper_dir():
  """Sets up a shadow toolchain.

  This sets up our clang wrapper for clang/clang++ and symlinks everything else
  to point to the real toolchain.
  """
  if _TOOLCHAIN_WITH_WRAPPER.exists():
    shutil.rmtree(_TOOLCHAIN_WITH_WRAPPER)
  _TOOLCHAIN_WITH_WRAPPER.mkdir(parents=True)

  # Set up symlinks to toolchain binaries.
  wrapper_bin_dir = _TOOLCHAIN_WITH_WRAPPER / 'bin'
  wrapper_bin_dir.mkdir()
  for name in os.listdir(_CLANG_TOOLCHAIN / 'bin'):
    # Symlink clang/llvm toolchain binaries, except for clang itself.
    # We have to be careful not to symlink other unrelated binaries, since other
    # parts of the build process may wrap those binaries (e.g.
    # make_build_replayable.py in OSS-Fuzz).
    if not name.startswith(CLANG_TOOLCHAIN_BINARY_PREFIXES):
      continue

    os.symlink(_CLANG_TOOLCHAIN / 'bin' / name, wrapper_bin_dir / name)
  os.symlink(_CLANG_TOOLCHAIN / 'lib', _TOOLCHAIN_WITH_WRAPPER / 'lib')

  # Set up our compiler wrappers.
  os.symlink(INDEXER_DIR / 'clang_wrapper.py', wrapper_bin_dir / 'clang')
  os.symlink(INDEXER_DIR / 'clang_wrapper.py', wrapper_bin_dir / 'clang++')


@dataclasses.dataclass(slots=True, frozen=True)
class BinaryMetadata:
  binary_config: manifest_types.CommandLineBinaryConfig
  build_id: str
  build_id_matches: bool
  compile_commands: list[dict[str, Any]]


def _get_build_id_from_elf_notes(elf_file: Path, contents: bytes) -> str | None:
  """Extracts the build id from the ELF notes of a binary.

  The ELF notes are obtained with
    `llvm-readelf --notes --elf-output-style=JSON`.

  Args:
    elf_file: The ELF file name.
    contents: The contents of the ELF notes, as a JSON string.

  Returns:
    The build id, or None if it could not be found.
  """

  try:
    elf_data = json.loads(contents)
  except json.JSONDecodeError:
    logging.error('failed to decode ELF notes for %s', elf_file)
    return None

  assert elf_data

  # Example output of llvm-readelf JSON output for llvm 19+:
  # [
  #   {
  #     "FileSummary": {
  #       "File": "binary",
  #       "Format": "elf64-x86-64",
  #       "Arch": "x86_64",
  #       "AddressSize": "64bit",
  #       "LoadName": "<Not found>"
  #     },
  #     "NoteSections": [
  #       {
  #         "NoteSection": {
  #           "Name": ".note.gnu.property",
  #           "Offset": 904,
  #           "Size": 32,
  #           "Notes": [
  #             {
  #               "Owner": "GNU",
  #               "Data size": 16,
  #               "Type": "NT_GNU_PROPERTY_TYPE_0 (property note)",
  #               "Property": [
  #                 "x86 ISA needed: x86-64-baseline"
  #               ]
  #             }
  #           ]
  #         }
  #       },
  #       {
  #         "NoteSection": {
  #           "Name": ".note.gnu.build-id",
  #           "Offset": 936,
  #           "Size": 36,
  #           "Notes": [
  #             {
  #               "Owner": "GNU",
  #               "Data size": 20,
  #               "Type": "NT_GNU_BUILD_ID (unique build ID bitstring)",
  #               "Build ID": "182a06c3dca5ee4d7e9c1d94b432c8bd9279438f"
  #             }
  #           ]
  #         }
  #       },
  #       {
  #         "NoteSection": {
  #           "Name": ".note.ABI-tag",
  #           "Offset": 1630064,
  #           "Size": 32,
  #           "Notes": [
  #             {
  #               "Owner": "GNU",
  #               "Data size": 16,
  #               "Type": "NT_GNU_ABI_TAG (ABI version tag)",
  #               "OS": "Linux",
  #               "ABI": "3.2.0"
  #             }
  #           ]
  #         }
  #       }
  #     ]
  #   }
  # ]

  for file_info in elf_data:
    if 'Notes' in file_info:
      # llvm < 19
      for note_entry in file_info['Notes']:
        note_section = note_entry['NoteSection']
        if note_section['Name'] == '.note.gnu.build-id':
          note_details = note_section['Note']
          if 'Build ID' in note_details:
            return note_details['Build ID']
    elif 'NoteSections' in file_info:
      # llvm 19+
      for note_entry in file_info['NoteSections']:
        note_section = note_entry['NoteSection']
        if note_section['Name'] == '.note.gnu.build-id':
          note_details = note_section['Notes']
          for note_detail in note_details:
            if 'Build ID' in note_detail:
              return note_detail['Build ID']
    else:
      raise ValueError('Unknown ELF notes format.')

  return None


def _get_clang_version(toolchain: Path) -> str:
  """Returns the clang version."""
  clang = toolchain / 'bin' / 'clang'
  clang_version = subprocess.run(
      [clang, '-dumpversion'], capture_output=True, check=True, text=True
  ).stdout
  return clang_version.split('.')[0]


def get_build_id(elf_file: Path) -> str | None:
  """This invokes llvm-readelf to get the build ID of the given ELF file."""
  ret = subprocess.run(
      [
          _LLVM_READELF_PATH,
          '--notes',
          '--elf-output-style=JSON',
          elf_file.as_posix(),
      ],
      capture_output=True,
      check=False,
  )
  if ret.returncode != 0:
    return None

  return _get_build_id_from_elf_notes(elf_file, ret.stdout)


def find_fuzzer_binaries(out_dir: Path, build_id: str) -> Sequence[Path]:
  """Find fuzzer binary with a given build ID."""
  binaries = []
  for root, _, files in os.walk(out_dir):
    for file in files:
      file_path = Path(root, file)
      if get_build_id(file_path) == build_id:
        binaries.append(file_path)

  return binaries


def enumerate_build_targets(
    binary_config: manifest_types.CommandLineBinaryConfig,
) -> Sequence[BinaryMetadata]:
  """Enumerates the build targets in the project.

  Args:
    binary_config: The binary config applied to all targets.

  Returns:
    A sequence of target descriptions, in BinaryMetadata form.
  """

  logging.info('enumerate_build_targets')
  linker_json_paths = list((OUT / 'cdb').glob('*_linker_commands.json'))

  logging.info('Found %i linker JSON files.', len(linker_json_paths))
  binary_to_build_metadata: dict[str, BinaryMetadata] = {}
  for linker_json_path in linker_json_paths:
    build_id = linker_json_path.name.split('_')[0]
    with linker_json_path.open('rt') as f:
      data = json.load(f)
      binary_path = Path(data['output'])
      name = binary_path.name

      # Some projects may move build files around, so being more careful about
      # the binary path and checking the build id should improve the success
      # rate.
      if (OUT / name).exists():
        # Just because the name matches, doesn't mean it's the right one for
        # this linker command.
        # Only set this if we haven't already found an exact build ID match.
        # We can't always rely on build ID matching, because some builds will
        # modify the binary after the linker runs.
        if (
            name in binary_to_build_metadata
            and binary_to_build_metadata[name].build_id_matches
        ):
          continue

        build_id_matches = build_id == get_build_id(binary_path)
        target_binary_config = manifest_types.CommandLineBinaryConfig(
            **dict(binary_config.to_dict(), binary_name=name)
        )
        binary_to_build_metadata[name] = BinaryMetadata(
            binary_config=target_binary_config,
            compile_commands=data['compile_commands'],
            build_id=build_id,
            build_id_matches=build_id_matches,
        )
      else:
        logging.info('trying to find %s with build id %s', name, build_id)
        binary_paths = find_fuzzer_binaries(OUT, build_id)
        logging.info('found matching binaries: %s', binary_paths)
        if not binary_paths:
          logging.error('could not find %s with build id %s', name, build_id)
          continue

        for binary_path in binary_paths:
          compile_commands = data['compile_commands']
          target_binary_config = manifest_types.CommandLineBinaryConfig(
              **dict(binary_config.to_dict(), binary_name=binary_path.name)
          )
          binary_to_build_metadata[binary_path.name] = BinaryMetadata(
              binary_config=target_binary_config,
              compile_commands=compile_commands,
              build_id=build_id,
              build_id_matches=True,
          )

  return tuple(binary_to_build_metadata.values())


def copy_fuzzing_engine(fuzzing_engine: str) -> Path:
  """Copy fuzzing engine."""
  # Not every project saves source to $SRC/$PROJECT_NAME
  fuzzing_engine_dir = SRC / PROJECT
  if not fuzzing_engine_dir.exists():
    fuzzing_engine_dir = SRC / 'fuzzing_engine'
    fuzzing_engine_dir.mkdir(exist_ok=True)

  shutil.copy(f'/opt/indexer/{fuzzing_engine}', fuzzing_engine_dir)
  return fuzzing_engine_dir


def _get_latest_gcc_version() -> str:
  """Finds the latest GCC version installed.

  Defaults to '9' for backward compatibility if detection fails.

  Returns:
    The latest GCC version found, or the default.
  """
  if _GCC_BASE_PATH.exists():
    versions = []
    for d in _GCC_BASE_PATH.iterdir():
      if d.is_dir() and d.name.isdigit():
        versions.append(int(d.name))

    if versions:
      return str(max(versions))

  return _DEFAULT_GCC_VERSION


def build_project(
    targets_to_index: Sequence[str] | None = None,
    compile_args: Sequence[str] | None = None,
    binaries_only: bool = False,
    coverage_flags: str = DEFAULT_COVERAGE_FLAGS,
):
  """Build the actual project."""
  set_env_vars(coverage_flags)
  if targets_to_index:
    os.environ['INDEXER_TARGETS'] = ','.join(targets_to_index)

  if binaries_only:
    os.environ['INDEXER_BINARIES_ONLY'] = '1'

  clang_version = _get_clang_version(_CLANG_TOOLCHAIN)
  write_compile_settings(
      CompileSettings(
          coverage_flags=coverage_flags,
          clang_toolchain=_CLANG_TOOLCHAIN.as_posix(),
          clang_version=clang_version,
      )
  )

  fuzzing_engine_dir = copy_fuzzing_engine(DEFAULT_FUZZING_ENGINE)
  gcc_version = _get_latest_gcc_version()
  build_fuzzing_engine_command = [
      f'{_CLANG_TOOLCHAIN}/bin/clang++',
      '-c',
      '-Wall',
      '-Wextra',
      '-pedantic',
      '-std=c++20',
      '-fno-rtti',
      '-fno-exceptions',
      '-glldb',
      '-O0',
      (fuzzing_engine_dir / DEFAULT_FUZZING_ENGINE).as_posix(),
      '-o',
      f'{OUT}/fuzzing_engine.o',
      '-gen-cdb-fragment-path',
      f'{OUT}/cdb',
      '-Qunused-arguments',
      f'-isystem {_CLANG_TOOLCHAIN}/lib/clang/{clang_version}',
      f'/usr/lib/gcc/x86_64-linux-gnu/{gcc_version}/../../../../include/c++/{gcc_version}',
      '-I',
      f'/usr/lib/gcc/x86_64-linux-gnu/{gcc_version}/../../../../include/x86_64-linux-gnu/c++/{gcc_version}',
      '-I',
      f'/usr/lib/gcc/x86_64-linux-gnu/{gcc_version}/../../../../include/c++/{gcc_version}/backward',
      '-I',
      f'{_CLANG_TOOLCHAIN}/lib/clang/{clang_version}/include',
      '-I',
      f'{_CLANG_TOOLCHAIN}/include',
      '-I',
      '/usr/include/x86_64-linux-gnu',
      '-I',
      '/usr/include',
  ]
  subprocess.run(build_fuzzing_engine_command, check=True, cwd='/opt/indexer')

  build_cov_instrumentation_command = [
      f'{_CLANG_TOOLCHAIN}/bin/clang++',
      '-fno-rtti',
      '-fno-exceptions',
      '-c',
      '/opt/indexer/coverage.cc',
  ]
  subprocess.run(
      build_cov_instrumentation_command, check=True, cwd='/opt/indexer'
  )

  ar_cmd = [
      'ar',
      'rcs',
      '/opt/indexer/fuzzing_engine.a',
      f'{OUT}/fuzzing_engine.o',
  ]
  subprocess.run(ar_cmd, check=True)
  lib_fuzzing_engine = '/usr/lib/libFuzzingEngine.a'
  if os.path.exists(lib_fuzzing_engine):
    os.remove(lib_fuzzing_engine)
  os.symlink('/opt/indexer/fuzzing_engine.a', lib_fuzzing_engine)

  compile_command = ['/usr/local/bin/compile']
  if compile_args:
    compile_command.extend(compile_args)

  subprocess.run(compile_command, check=True)


def test_target(
    target: BinaryMetadata,
) -> bool:
  """Tests a single target."""
  target_path = OUT / target.binary_config.binary_name
  result = subprocess.run(
      [str(target_path)], stderr=subprocess.PIPE, check=False
  )
  expected_error = f'Usage: {target_path} <input_file>\n'
  if expected_error not in result.stderr.decode() or result.returncode != 1:
    logging.error(
        'Target %s failed to run: %s',
        target_path,
        result.stderr.decode(),
    )
    return False
  return True


def set_interpreter(target_path: Path, lib_mount_path: pathlib.PurePath):
  subprocess.run(
      [
          'patchelf',
          '--set-interpreter',
          (lib_mount_path / _LD_BINARY).as_posix(),
          target_path.as_posix(),
      ],
      check=True,
  )


def set_target_rpath(binary_artifact: Path, lib_mount_path: pathlib.PurePath):
  subprocess.run(
      [
          'patchelf',
          '--set-rpath',
          lib_mount_path,
          '--force-rpath',
          binary_artifact.as_posix(),
      ],
      check=True,
  )


def copy_shared_libraries(
    fuzz_target_path: Path, libs_path: Path, lib_mount_path: pathlib.PurePath
) -> None:
  """Copies the shared libraries to the shared directory."""
  env = os.environ.copy()
  env['LD_TRACE_LOADED_OBJECTS'] = '1'
  env['LD_BIND_NOW'] = '1'
  # TODO: Should we take ld.so from interp?

  res = subprocess.run(
      [_LD_PATH.as_posix(), fuzz_target_path.as_posix()],
      capture_output=True,
      env=env,
      check=True,
  )

  output = res.stdout.decode()
  if 'statically linked' in output:
    return

  # Example output:
  #       linux-vdso.so.1 =>  (0x00007f40afc0f000)
  #       linux-vdso.so.1 (0x00007f76b9377000)
  #       lib foo.so => /tmp/sharedlib/lib foo.so (0x00007f76b9367000)
  #       libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f76b9157000)
  #       /lib64/ld-linux-x86-64.so.2 (0x00007f76b9379000)
  #
  # The lines that do not have a => should be skipped.
  # The dynamic linker should always be copied.
  # The lines that have a => could contain a space, but we copy whatever on the
  # right side of the =>, removing the load address.
  shutil.copy2(_LD_PATH, libs_path / _LD_PATH.name)

  lines = output.splitlines()
  for line in lines:
    if '=>' not in line:
      continue
    parts = line.split('=>')
    lib_name = parts[0].strip()
    right_side = parts[1].strip().rsplit(' ', maxsplit=1)[0].strip()
    if not right_side:
      continue
    library_path = Path(right_side)
    logging.info('Copying %s => %s', lib_name, library_path)
    if library_path.is_relative_to(libs_path):
      # This can happen if the project build is doing the same thing as us and
      # already copied the library to the library_path.
      continue

    try:
      shutil.copy2(library_path, libs_path / library_path.name)
      dst = libs_path / library_path.name
      # Need to preserve world writeable permissions.
      shutil.copy2(library_path, dst)
      # If we don't do this, our shared objects load the system's shared
      # objects. What about their shared objects you may ask? Well they
      # will all be from this directory where every so has the directory
      # as its rpath.
      set_target_rpath(dst, lib_mount_path)

    except FileNotFoundError as e:
      logging.exception('Could not copy %s', library_path)
      raise e


def archive_target(target: BinaryMetadata, file_extension: str) -> Path | None:
  """Archives a single target in the project using the exported rootfs."""
  logging.info('archive_target %s', target.binary_config.binary_name)
  index_dir = INDEXES_PATH / target.build_id
  if not index_dir.exists():
    logging.error("didn't find index dir %s", index_dir)
    return None

  source_map = subprocess.run(
      ['srcmap'], capture_output=True, check=True
  ).stdout

  target_hash = hashlib.sha256(source_map).hexdigest()[:16]

  name = f'{PROJECT}.{target.binary_config.binary_name}'
  uuid = f'{PROJECT}.{target.binary_config.binary_name}.{target_hash}'
  lib_mount_path = pathlib.Path('/tmp') / (uuid + '_lib')

  libs_path = OUT / 'lib'
  # Keep a backup of the original 'lib' dir, in case the upstream project also
  # bundles libs using the same directory name.
  libs_backup_path = OUT / 'lib.backup'

  if libs_path.exists():
    shutil.copytree(libs_path, libs_backup_path)
  else:
    libs_path.mkdir(parents=False)

  target_path = OUT / target.binary_config.binary_name
  copy_shared_libraries(target_path, libs_path, lib_mount_path)

  # We may want to eventually re-enable SRC copying (with some filtering to only
  # include source files).
  with tempfile.TemporaryDirectory() as empty_src_dir, \
       tempfile.TemporaryDirectory() as backup_dir:
    # Make a backup of the target binary so we can undo the rpath/interpreter
    # changes in OUT.
    backup_path = Path(backup_dir) / target_path.name
    shutil.copy2(target_path, backup_path)
    # This is to handle `target_path` being a hard link, where other target
    # binaries share the same inode.
    os.unlink(target_path)
    shutil.copy2(backup_path, target_path)

    set_interpreter(target_path, lib_mount_path)
    set_target_rpath(target_path, lib_mount_path)
    archive_path = SNAPSHOT_DIR / f'{uuid}{file_extension}'
    # For `/` in $PROJECT.
    archive_path.parent.mkdir(parents=True, exist_ok=True)

    manifest_types.Manifest(
        name=name,
        uuid=uuid,
        binary_config=target.binary_config,
        source_map=manifest_types.source_map_from_dict(json.loads(source_map)),
        lib_mount_path=lib_mount_path,
    ).save_build(
        source_dir=Path(empty_src_dir),
        build_dir=OUT,
        index_dir=index_dir,
        archive_path=archive_path,
        out_dir=OUT,
    )

    shutil.move(backup_path, target_path)

  logging.info('Wrote archive to: %s', archive_path)
  shutil.rmtree(libs_path)
  if libs_backup_path.exists():
    shutil.move(libs_backup_path, libs_path)

  return archive_path


def test_and_archive(
    binary_config: manifest_types.CommandLineBinaryConfig,
    targets_to_index: Sequence[str] | None,
    file_extension: str,
):
  """Test target and archive."""
  targets = enumerate_build_targets(binary_config)
  if targets_to_index:
    targets = [
        t for t in targets if t.binary_config.binary_name in targets_to_index
    ]
    missing_targets = set(targets_to_index) - set(
        t.binary_config.binary_name for t in targets
    )
    if missing_targets:
      raise ValueError(f'Could not find specified targets {missing_targets}.')

  logging.info('targets %s', targets)
  for target in targets:
    try:
      # Check that the target binary behaves like a fuzz target,
      # unless the caller specifically asked for a list of targets.
      if not targets_to_index and not test_target(target):
        # TODO: Figure out if this is a good idea, it makes some things
        # pass that should but causes some things to pass that shouldn't.
        continue
    except Exception:  # pylint: disable=broad-exception-caught
      logging.exception('Error testing target.')
      continue
    archive_target(target, file_extension)


def clear_out():
  """Clean up the OUT directory."""
  for i in OUT.iterdir():
    if i.is_dir():
      shutil.rmtree(i)
    else:
      i.unlink()


def main():
  logging.basicConfig(level=logging.INFO)

  parser = argparse.ArgumentParser(description='Index builder.')
  parser.add_argument(
      '-t',
      '--targets',
      help=(
          'Comma separated list of targets to build for. '
          'If this is omitted, snapshots are built for all fuzz targets. '
          'If specified, this can include binaries which are not fuzz targets '
          '(e.g., CLI targets which are built as part of the build '
          'integration).'
      ),
  )
  parser.add_argument(
      '--targets-all-index',
      action='store_true',
      help=(
          'When -t/--targets is set, allow the indexer to run on all of them, '
          'but only archive snapshots for the specified targets. This is '
          'useful to save some time for projects where the binary name during '
          'build time does not match the final name in the output directory.'
      ),
  )
  parser.add_argument(
      '--target-args',
      default=None,
      help=(
          'Arguments to pass to the target when executing it. '
          'This string is shell-escaped (interpreted with `shlex.split`). '
          'The substring <input_file> will be replaced with the input path.'
          'Note: This is deprecated, use --target-arg instead.'
      ),
  )
  parser.add_argument(
      '--target-arg',
      action='append',
      help=(
          'An argument to pass to the target binary. '
          'The substring <input_file> will be replaced with the input path.'
          'If you want to pass custom args, pass --harness-kind=binary as well.'
      ),
  )
  parser.add_argument(
      '--target-env',
      action='append',
      default=[],
      help=(
          'Environment variables (key=value) to pass to the target when '
          'executing it. The substring <input_file> in a value will be '
          'replaced with the input path.'
      ),
  )
  parser.add_argument(
      '--binary-config',
      default=None,
      help=(
          'JSON serialized OSS_FUZZ BinaryConfig object containing '
          'binary_args, binary_env, harness_kind, etc. If this value is set, '
          'redundant flags like target-arg, etc., may not be used. '
          'The binary_name field of this BinaryConfig object is ignored, all '
          'other fields will be applied to all targets.'
      ),
  )
  parser.add_argument(
      '--no-clear-out',
      action='store_true',
      help='Do not clear out the OUT directory before building.',
  )
  parser.add_argument(
      '--compile-arg',
      action='append',
      help='An argument to pass to the `compile` script.',
  )
  parser.add_argument(
      '--compressed',
      action='store_true',
      help='Use gzipped tar (.tgz) for the output snapshot',
  )
  parser.add_argument(
      '--binaries-only',
      action='store_true',
      help='Build target binaries only, and not index archives.',
  )
  parser.add_argument(
      '--harness-kind',
      choices=[str(x) for x in manifest_types.HarnessKind],
      default=manifest_types.HarnessKind.LIBFUZZER,
      help=(
          'The harness kind to use for the fuzz target. In order to pass custom'
          ' args, set this to binary.'
      ),
  )
  parser.add_argument(
      '--tracing-instrumentation',
      action='store_true',
      help='Enable tracing coverage instrumentation.',
  )
  args = parser.parse_args()

  INDEXES_PATH.mkdir(exist_ok=True)
  INCREMENTAL_CDB_PATH.mkdir(exist_ok=True)

  # Clean up the existing OUT by default, otherwise we may run into various
  # build errors.
  if not args.no_clear_out:
    clear_out()

  if args.target_args and args.target_arg:
    raise ValueError(
        'Only one of --target-args or --target-arg can be specified.'
    )

  if args.binary_config:
    if (
        args.target_arg
        or args.target_args
        or args.target_env
        or args.harness_kind != manifest_types.HarnessKind.LIBFUZZER
    ):
      raise ValueError(
          'If --binary-config is specified, redundant flags may not be set.'
      )

    binary_config = manifest_types.BinaryConfig.from_dict(
        json.loads(args.binary_config)
    )
    if (
        binary_config.kind != manifest_types.BinaryConfigKind.OSS_FUZZ
        or not isinstance(binary_config, manifest_types.CommandLineBinaryConfig)
    ):
      raise ValueError(
          'Only OSS_FUZZ binary configs are supported with --binary-config.'
      )
  else:
    if args.target_args and args.target_arg:
      raise ValueError(
          'Only one of --target-args or --target-arg can be specified.'
      )
    elif args.target_arg:
      target_args = args.target_arg
    elif args.target_args:
      logging.warning('--target-args is deprecated, use --target-arg instead.')
      target_args = shlex.split(args.target_args)
    else:
      logging.info('No target args specified.')
      target_args = []
    if args.target_env:
      target_env = manifest_types.parse_env(args.target_env)
    else:
      logging.info('No target env specified.')
      target_env = {}

    harness_kind = manifest_types.HarnessKind(args.harness_kind)

    match harness_kind:
      case manifest_types.HarnessKind.LIBFUZZER:
        if target_args and target_args != [manifest_types.INPUT_FILE]:
          raise ValueError(
              'Unsupported target args for harness_kind libfuzzer:'
              f' {target_args}'
          )
        target_args = [manifest_types.INPUT_FILE]
      case _:
        pass

    binary_config = manifest_types.CommandLineBinaryConfig(
        kind=manifest_types.BinaryConfigKind.OSS_FUZZ,
        binary_name='oss-fuzz',  # The name will be replaced with the target.
        binary_args=target_args,
        binary_env=target_env,
        harness_kind=harness_kind,
    )

  targets_to_index = None
  if args.targets:
    targets_to_index = args.targets.split(',')

  for directory in ['aflplusplus', 'fuzztest', 'honggfuzz', 'libfuzzer']:
    path = os.path.join(os.environ['SRC'], directory)
    shutil.rmtree(path, ignore_errors=True)

  # Initially, we put snapshots directly in /out. This caused a bug where each
  # snapshot was added to the next because they contain the contents of /out.
  SNAPSHOT_DIR.mkdir(exist_ok=True)
  # We don't have an existing /out dir on oss-fuzz's build infra.
  OUT.mkdir(parents=True, exist_ok=True)

  set_up_wrapper_dir()
  build_project(
      None if args.targets_all_index else targets_to_index,
      args.compile_arg,
      args.binaries_only,
      TRACING_COVERAGE_FLAGS
      if args.tracing_instrumentation
      else DEFAULT_COVERAGE_FLAGS,
  )

  if not args.binaries_only:
    file_extension = '.tgz' if args.compressed else '.tar'

    test_and_archive(binary_config, targets_to_index, file_extension)

    for snapshot in SNAPSHOT_DIR.iterdir():
      shutil.move(str(snapshot), OUT)

  # By default, this directory has o-rwx and its contents can't be deleted
  # by a non-root user from outside the container. The rest of the files are
  # unaffected because to delete a file, a write permission on its enclosing
  # directory is sufficient regardless of the owner.
  cdb_dir = OUT / 'cdb'
  try:
    cdb_dir.chmod(
        cdb_dir.stat().st_mode | stat.S_IROTH | stat.S_IWOTH | stat.S_IXOTH
    )
  except OSError:
    pass


if __name__ == '__main__':
  main()
