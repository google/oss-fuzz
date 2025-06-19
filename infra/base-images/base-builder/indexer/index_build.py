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
import subprocess
import tempfile
from typing import Any, Sequence

import manifest_types
import pathlib

PROJECT = Path(os.environ['PROJECT_NAME']).name
SNAPSHOT_DIR = Path('/snapshot')
SRC = Path(os.getenv('SRC', '/src'))
# On OSS-Fuzz build infra, $OUT is not /out.
OUT = Path(os.getenv('OUT', '/out'))
INDEXES_PATH = Path(os.getenv('INDEXES_PATH', '/indexes'))

_LD_BINARY = 'ld-linux-x86-64.so.2'
_LD_PATH = Path('/lib64') / _LD_BINARY
_LLVM_READELF_PATH = '/usr/local/bin/llvm-readelf'
_CLANG_VERSION = '18'


def set_env_vars():
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
  os.environ['PATH'] = f"/opt/indexer:{os.environ.get('PATH')}"


def set_up_wrapper_dir():
  """Set up symlinks to everything in /usr/local/bin/.

  Do this so build systems that snoop around clang's directory don't explode.
  """
  real_dir = '/usr/local/bin'
  indexer_dir = '/opt/indexer'
  for name in os.listdir():
    src = os.path.join(real_dir, name)
    dst = os.path.join(indexer_dir, name)
    if name not in {'clang', 'clang++'}:
      continue
    os.symlink(src, dst)


@dataclasses.dataclass(slots=True)
class BinaryMetadata:
  name: str
  binary_path: Path
  binary_args: list[str]
  build_id: str
  compile_commands: list[dict[str, Any]]


def _get_build_id_from_elf_notes(contents: bytes) -> str | None:
  """Extracts the build id from the ELF notes of a binary.

  The ELF notes are obtained with
    `llvm-readelf --notes --elf-output-style=JSON`.

  Args:
    contents: The contents of the ELF notes, as a JSON string.

  Returns:
    The build id, or None if it could not be found.
  """

  elf_data = json.loads(contents)
  assert elf_data

  for file_info in elf_data:
    for note_entry in file_info['Notes']:
      note_section = note_entry['NoteSection']
      if note_section['Name'] == '.note.gnu.build-id':
        note_details = note_section['Note']
        if 'Build ID' in note_details:
          return note_details['Build ID']
  return None


def get_build_id(elf_file: str) -> str | None:
  """This invokes llvm-readelf to get the build ID of the given ELF file."""

  # Note: this format changed in llvm-readelf19.
  # Example output of llvm-readelf JSON output:
  # [
  #   {
  #     "FileSummary": {
  #       "File": "/out/iccprofile_info",
  #       "Format": "elf64-x86-64",
  #       "Arch": "x86_64",
  #       "AddressSize": "64bit",
  #       "LoadName": "<Not found>",
  #     },
  #     "Notes": [
  #       {
  #         "NoteSection": {
  #           "Name": ".note.ABI-tag",
  #           "Offset": 764,
  #           "Size": 32,
  #           "Note": {
  #             "Owner": "GNU",
  #             "Data size": 16,
  #             "Type": "NT_GNU_ABI_TAG (ABI version tag)",
  #             "OS": "Linux",
  #             "ABI": "3.2.0",
  #           },
  #         }
  #       },
  #       {
  #         "NoteSection": {
  #           "Name": ".note.gnu.build-id",
  #           "Offset": 796,
  #           "Size": 24,
  #           "Note": {
  #             "Owner": "GNU",
  #             "Data size": 8,
  #             "Type": "NT_GNU_BUILD_ID (unique build ID bitstring)",
  #             "Build ID": "a03df61c5b0c26f3",
  #           },
  #         }
  #       },
  #     ],
  #   }
  # ]

  ret = subprocess.run(
      [
          _LLVM_READELF_PATH,
          '--notes',
          '--elf-output-style=JSON',
          elf_file,
      ],
      capture_output=True,
      check=False,
  )
  if ret.returncode != 0:
    return None

  return _get_build_id_from_elf_notes(ret.stdout)


def find_fuzzer_binary(out_dir: Path, build_id: str) -> Path | None:
  """Find fuzzer binary with a given build ID."""
  for root, _, files in os.walk(out_dir):
    for file in files:
      if get_build_id(os.path.join(root, file)) == build_id:
        return Path(root, file)

  return None


def enumerate_build_targets(
    binary_args: list[str],) -> Sequence[BinaryMetadata]:
  """Enumerates the build targets in the project.

  Args:
    binary_args: Argument list, applied to all targets

  Returns:
    A sequence of target descriptions, in BinaryMetadata form.
  """

  logging.info('enumerate_build_targets')
  linker_json_paths = list((OUT / 'cdb').glob('*_linker_commands.json'))

  targets = []
  logging.info('Found %i linker JSON files.', len(linker_json_paths))
  for linker_json_path in linker_json_paths:
    build_id = linker_json_path.name.split('_')[0]
    with linker_json_path.open('rt') as f:
      data = json.load(f)
      binary_path = Path(data['output'])
      name = binary_path.name

      # Some projects may move build files around, so being more careful about
      # the binary path and checking the build id should improve the success
      # rate.
      if not (OUT / name).exists():
        logging.info('trying to find %s with build id %s', name, build_id)
        binary_path = find_fuzzer_binary(OUT, build_id)
        if not binary_path:
          logging.error('could not find %s with build id %s', name, build_id)
          continue

        name = binary_path.name

      compile_commands = data['compile_commands']

      if binary_path.is_relative_to(f'{OUT}/'):
        binary_path = Path('./build', binary_path.relative_to(f'{OUT}/'))

      targets.append(
          BinaryMetadata(
              name=name,
              binary_path=binary_path,
              binary_args=binary_args,
              compile_commands=compile_commands,
              build_id=build_id,
          ))

  return targets


def copy_fuzzing_engine() -> Path:
  """Copy fuzzing engine."""
  # Not every project saves source to $SRC/$PROJECT_NAME
  fuzzing_engine_dir = SRC / PROJECT
  if not fuzzing_engine_dir.exists():
    fuzzing_engine_dir = SRC / 'fuzzing_engine'
    fuzzing_engine_dir.mkdir()

  shutil.copy('/opt/indexer/fuzzing_engine.cc', fuzzing_engine_dir)
  return fuzzing_engine_dir


def build_project(targets_to_index: Sequence[str] | None = None):
  """Build the actual project."""
  set_env_vars()
  existing_cflags = os.environ.get('CFLAGS', '')
  extra_flags = ('-fno-omit-frame-pointer '
                 '-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION '
                 '-O0 -glldb '
                 '-fsanitize=address '
                 '-Wno-invalid-offsetof '
                 '-fsanitize-coverage=bb,no-prune,trace-pc-guard '
                 f'-gen-cdb-fragment-path {OUT}/cdb '
                 '-Qunused-arguments '
                 f'-isystem /usr/local/lib/clang/{_CLANG_VERSION} '
                 f'-resource-dir /usr/local/lib/clang/{_CLANG_VERSION} ')
  os.environ['CFLAGS'] = f'{existing_cflags} {extra_flags}'.strip()
  if targets_to_index:
    os.environ['INDEXER_TARGETS'] = ','.join(targets_to_index)

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
      str(fuzzing_engine_path / 'fuzzing_engine.cc'),
      '-o',
      f'{OUT}/fuzzing_engine.o',
      '-gen-cdb-fragment-path',
      f'{OUT}/cdb',
      '-Qunused-arguments',
      f'-isystem /usr/local/lib/clang/{_CLANG_VERSION}',
      '/usr/lib/gcc/x86_64-linux-gnu/9/../../../../include/c++/9',
      '-I',
      '/usr/lib/gcc/x86_64-linux-gnu/9/../../../../include/x86_64-linux-gnu/c++/9',
      '-I',
      '/usr/lib/gcc/x86_64-linux-gnu/9/../../../../include/c++/9/backward',
      '-I',
      f'/usr/local/lib/clang/{_CLANG_VERSION}/include',
      '-I',
      '/usr/local/include',
      '-I',
      '/usr/include/x86_64-linux-gnu',
      '-I',
      '/usr/include',
  ]
  subprocess.run(build_fuzzing_engine_command, check=True, cwd='/opt/indexer')
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
  set_up_wrapper_dir()
  subprocess.run(['/usr/local/bin/compile'], check=True)


def test_target(target: BinaryMetadata,) -> bool:
  """Tests a single target."""
  target_path = OUT / target.name
  result = subprocess.run([str(target_path)],
                          stderr=subprocess.PIPE,
                          check=False)
  expected_error = f'Usage: {target_path} <input_file>\n'
  if result.stderr.decode() != expected_error or result.returncode != 1:
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


def copy_shared_libraries(fuzz_target_path: Path, libs_path: Path,
                          lib_mount_path: pathlib.PurePath) -> None:
  """Copies the shared libraries to the shared directory."""
  env = os.environ.copy()
  env['LD_TRACE_LOADED_OBJECTS'] = '1'
  env['LD_BIND_NOW'] = '1'
  # TODO(unassigned): Should we take ld.so from interp?

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


def archive_target(target: BinaryMetadata) -> Path | None:
  """Archives a single target in the project using the exported rootfs."""
  logging.info('archive_target %s', target.name)
  index_dir = INDEXES_PATH / target.build_id
  if not index_dir.exists():
    logging.error("didn't find index dir %s", index_dir)
    return None

  source_map = subprocess.run(['srcmap'], capture_output=True,
                              check=True).stdout

  target_hash = hashlib.sha256(source_map).hexdigest()[:16]

  name = f'{PROJECT}.{target.name}'
  uuid = f'{PROJECT}.{target.name}.{target_hash}'
  lib_mount_path = pathlib.Path('/tmp') / (uuid + '_lib')

  libs_path = OUT / 'lib'
  libs_path.mkdir(parents=False, exist_ok=True)
  target_path = OUT / target.name
  copy_shared_libraries(target_path, libs_path, lib_mount_path)
  set_interpreter(target_path, lib_mount_path)
  set_target_rpath(target_path, lib_mount_path)
  archive_path = SNAPSHOT_DIR / f'{uuid}.tar'
  archive_path.parent.mkdir(parents=True, exist_ok=True)  # For `/` in $PROJECT.

  # We may want to eventually re-enable SRC copying (with some filtering to only
  # include source files).
  with tempfile.TemporaryDirectory() as empty_src_dir:
    manifest_types.Manifest(
        name=name,
        uuid=uuid,
        binary_config=manifest_types.CommandLineBinaryConfig(
            kind=manifest_types.BinaryConfigKind.OSS_FUZZ,
            binary_name=target.name,
            binary_args=target.binary_args,
        ),
        source_map=manifest_types.source_map_from_dict(json.loads(source_map)),
        lib_mount_path=lib_mount_path,
    ).save_build(
        source_dir=Path(empty_src_dir),
        build_dir=OUT,
        index_dir=index_dir,
        archive_path=archive_path,
        out_dir=OUT,
    )

  logging.info('Wrote archive to: %s', archive_path)
  # TODO(ochang): this will break projects that also create a `libs` folder and
  # have multiple targets.
  shutil.rmtree(libs_path)

  return archive_path


def test_and_archive(target_args: list[str],
                     targets_to_index: Sequence[str] | None):
  """Test target and archive."""
  targets = enumerate_build_targets(target_args)
  if targets_to_index:
    targets = [t for t in targets if t.name in targets_to_index]
    missing_targets = set(targets_to_index) - set(t.name for t in targets)
    if missing_targets:
      raise ValueError(f'Could not find specified targets {missing_targets}.')

  logging.info('targets %s', targets)
  for target in targets:
    try:
      # Check that the target binary behaves like a fuzz target,
      # unless the caller specifically asked for a list of targets.
      if not targets_to_index and not test_target(target):
        # TODO(metzman): Figure out if this is a good idea, it makes some things
        # pass that should but causes some things to pass that shouldn't.
        continue
    except Exception:  # pylint: disable=broad-exception-caught
      logging.exception('Error testing target.')
      continue
    archive_target(target)


def clear_out():
  """Clean up the OUT directory."""
  for i in OUT.iterdir():
    if i.is_dir():
      shutil.rmtree(i)
    else:
      i.unlink()


def main():
  logging.basicConfig(level=logging.INFO)
  INDEXES_PATH.mkdir(exist_ok=True)

  # Clean up the existing OUT, otherwise we may run into various build errors.
  clear_out()

  parser = argparse.ArgumentParser(description='Index builder.')
  parser.add_argument(
      '-t',
      '--targets',
      help=(
          'Comma separated list of targets to build for. '
          'If this is omitted, snapshots are built for all fuzz targets. '
          'If specified, this can include binaries which are not fuzz targets '
          '(e.g., CLI targets which are built as part of the build '
          'integration).'),
  )
  parser.add_argument(
      '--target-args',
      default=None,
      help=('Arguments to pass to the target when executing it. '
            'This string is shell-escaped (interpreted with `shlex.split`). '
            'The substring <input_file> will be replaced with the input path.'
            'Note: This is deprecated, use --target-arg instead.'),
  )
  parser.add_argument(
      '--target-arg',
      action='append',
      help=('An argument to pass to the target binary. '
            'The substring <input_file> will be replaced with the input path.'),
  )
  args = parser.parse_args()

  if args.target_args and args.target_arg:
    raise ValueError(
        'Only one of --target-args or --target-arg can be specified.')

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
  build_project(targets_to_index)

  if args.target_arg:
    target_args = args.target_arg
  elif args.target_args:
    logging.warning('--target-args is deprecated, use --target-arg instead.')
    target_args = shlex.split(args.target_args)
  else:
    logging.info('No target args specified.')
    target_args = []

  test_and_archive(target_args, targets_to_index)

  for snapshot in SNAPSHOT_DIR.iterdir():
    shutil.move(str(snapshot), OUT)


if __name__ == '__main__':
  main()
