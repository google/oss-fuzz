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
"""
This is copied into the OSS-Fuzz container image and run there as part of the
instrumentation process.
"""

from collections.abc import MutableSequence, Sequence
import hashlib
import json
import os
from pathlib import Path
import subprocess
import shutil
import sqlite3
import sys
import time
from typing import Any, Sequence, Iterator

INDEX_DB_NAME = "db.sqlite"
_LLVM_READELF_PATH = "/usr/local/bin/llvm-readelf"
_INDEXER_PATH = "/opt/indexer/indexer"
_IGNORED_DEPS_PATH = os.path.join(os.path.dirname(_INDEXER_PATH),
                                  "ignored_deps.json")

PROJECT = Path(os.environ['PROJECT_NAME'])
SRC = Path(os.getenv('SRC', '/src'))
# On OSS-Fuzz build infra, $OUT is not /out.
OUT = Path(os.getenv('OUT', '/out'))
INDEXES_PATH = Path(os.getenv('INDEXES_PATH', '/indexes'))


def execute(argv: list[str]) -> None:
  argv[0] = os.path.join("/usr/local/bin/", os.path.basename(argv[0]))
  print("About to execute...", argv)
  os.execv(argv[0], argv)


def run(argv: list[str]) -> None:
  argv[0] = os.path.join("/usr/local/bin/", os.path.basename(argv[0]))
  print("About to run...", argv)
  ret = subprocess.run(argv, check=False)
  if ret.returncode != 0:
    sys.exit(ret.returncode)


def sha256(file: str) -> str:
  hash_value = hashlib.sha256()
  with open(file, "rb") as f:
    # python 3.11 is too new, this doesn't work on the oss-fuzz image.
    # hashlib.file_digest(f, lambda: hash_value)
    for chunk in iter(lambda: f.read(4096), b""):
      hash_value.update(chunk)
  return hash_value.hexdigest()


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
    for note_entry in file_info["Notes"]:
      note_section = note_entry["NoteSection"]
      if note_section["Name"] == ".note.gnu.build-id":
        note_details = note_section["Note"]
        if "Build ID" in note_details:
          return note_details["Build ID"]
  return None


def get_build_id(elf_file: str) -> str | None:
  """This invokes llvm-readelf to get the build ID of the given ELF file."""

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
          "--notes",
          "--elf-output-style=JSON",
          elf_file,
      ],
      capture_output=True,
      check=True,
  )
  if ret.returncode != 0:
    sys.exit(ret.returncode)

  return _get_build_id_from_elf_notes(ret.stdout)


def get_flag_value(argv: Sequence[str], flag: str) -> str | None:
  for i in range(len(argv) - 1):
    if argv[i] == flag:
      return argv[i + 1]
    elif flag == "-o" and argv[i].startswith(flag):
      return argv[i][2:]
  return None


def remove_flag_and_value(argv: list[str],
                          flag: str) -> MutableSequence[str] | None:
  for i in range(len(argv) - 1):
    if argv[i] == flag:
      return argv[:i] + argv[i + 2:]
    elif flag == "-o" and argv[i].startswith(flag):
      return argv[:i] + argv[i + 2:]

  return None


def parse_dependency_file(file_path: str, output_file: str,
                          ignored_deps: frozenset[str]) -> Sequence[str]:
  """Parses the dependency file generated by the linker."""
  output_file = os.path.realpath(output_file)
  output_file_line = f"{output_file}: \\"
  with open(file_path, "r") as f:
    lines = [line.strip() for line in f]
  assert output_file_line.endswith(
      lines[0].lstrip(".").lstrip("/")  # Account for relative paths.
  ), f"{lines[0]} is not a suffix of {output_file_line} {sys.argv} {os.getcwd()}"

  deps = []
  ignored_dep_paths = ["/usr", "/clang", "/lib"]
  for line in lines[1:]:
    if not line:
      break
    if line.endswith(" \\"):
      line = line[:-2]
    dep = os.path.realpath(line)
    # We don"t care about system-wide dependencies.
    if any([True for p in ignored_dep_paths if dep.startswith(p)]):
      continue
    if dep in ignored_deps:
      continue
    deps.append(dep)
  return deps


def files_by_creation_time(folder_path: str) -> Sequence[str]:
  files = [
      os.path.join(folder_path, file)
      for file in os.listdir(folder_path)
      if os.path.isfile(os.path.join(folder_path, file))
  ]
  files.sort(key=os.path.getctime)
  return files


def read_cdb_fragments(cdb_path: str) -> Any:
  """Iterates through the CDB fragments to reconstruct the compile commands."""
  files = files_by_creation_time(cdb_path)
  contents = []
  for file in files:
    # Don't read previously generated linker commands files.
    if file.endswith("_linker_commands.json"):
      continue
    if not file.endswith(".json"):
      continue
    for _ in range(3):
      with open(file, "rt") as f:
        data = f.read()
        if data.endswith(",\n"):
          contents.append(data[:-2])
          break
      print(f"Invalid compile commands file {file}: {data}\nDONEMARKER")
      time.sleep(10)
    else:
      # Some build systems seem to have a weird issue where the autotools
      # generated `test.c` for testing compilers doesn't result in valid cdb
      # fragments.
      if '/test.c' not in file:
        raise RuntimeError(
            f"Invalid compile commands file {file}: {data}\nDONEMARKER")

  contents = ",\n".join(contents)
  contents = "[" + contents + "]"
  return json.loads(contents)


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


def run_indexer(build_id: str, linker_commands: dict):
  """Run the indexer."""
  index_dir = INDEXES_PATH / build_id
  # TODO: check if this is correct.
  index_dir.mkdir(exist_ok=True)
  index_db_path = str(index_dir / INDEX_DB_NAME)

  # Use a build-specific compile commands directory, since there could be
  # parallel linking happening at the same time.
  compile_commands_dir = INDEXES_PATH / f"compile_commands_{build_id}"
  try:
    compile_commands_dir.mkdir(exist_ok=False)
  except FileExistsError:
    # Somehow we've already seen this link command, don't try to redo the indexing.
    # TODO: check if this is the safest behaviour.
    return

  with (compile_commands_dir / "compile_commands.json").open("wt") as f:
    json.dump(linker_commands["compile_commands"], f, indent=2)

  cmd = [
      _INDEXER_PATH, '--build_dir', compile_commands_dir, '--index_path',
      index_db_path, '--source_dir',
      str(SRC)
  ]
  result = subprocess.run(cmd, check=True)
  if result.returncode != 0:
    raise Exception("Running indexer failed\n"
                    f"stdout:\n```\n{result.stdout.decode()}\n```\n"
                    f"stderr:\n```\n{result.stderr.decode()}\n```\n")

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
      else:
        raise FileNotFoundError(
            f"Absolute file path {file_path} is not in the sysroot or clang "
            " include directory.")
    else:
      file_path = SRC / file_path
      index_path = relative_root / file_path.relative_to(str(SRC))

    if not file_path.is_dir() and file_path.exists():
      index_path.parent.mkdir(parents=True, exist_ok=True)
      shutil.copyfile(file_path, index_path)


def main(argv: list[str]) -> None:
  fuzzer_engine = os.getenv("LIB_FUZZING_ENGINE", "/usr/lib/libFuzzingEngine.a")

  # Projects like cups might assume these arguments.
  wrapper_log = OUT / 'wrapper-log'
  fuzzing_engine_in_argv = False
  idx = 0
  for arg in argv[:]:
    if arg == "-fsanitize=fuzzer":
      argv[idx] = "-lFuzzingEngine"
      os.system(f"echo replaced -fsanitizefuzzer >> {wrapper_log}")
      fuzzing_engine_in_argv = True
    elif arg == "-fsanitize=fuzzer-no-link":
      argv.remove("-fsanitize=fuzzer-no-link")
      idx -= 1
      os.system(f"echo Removed -fsanitizefuzzer-no-link >> {wrapper_log}")
    elif "-fsanitize=" in arg and "fuzzer" in arg:
      # This could be -fsanitize=address,fuzzer.
      os.system(f"echo replaced {arg} >> {wrapper_log}")
      sanitize_vals = arg.split('=')[1].split(",")
      sanitize_vals.remove("fuzzer")
      arg = "-fsanitize=" + ",".join(sanitize_vals)

      argv[idx] = arg
      idx += 1
      argv.insert(idx, "-lFuzzingEngine")
      fuzzing_engine_in_argv = True

    idx += 1

    if 'libFuzzingEngine.a' in arg or '-lFuzzingEngine' in arg:
      fuzzing_engine_in_argv = True

  # If we are not linking the fuzzing engine, execute normally.
  if not fuzzing_engine_in_argv:
    execute(argv)

  print(f'Linking {argv}')

  # We are linking, collect the relevant flags and dependencies.
  output_file = get_flag_value(argv, "-o")
  assert output_file, f"Missing output file: {argv}"

  if output_file.endswith(".o"):
    print("not a real linker command.")
    execute(argv)

  cdb_path = get_flag_value(argv, "-gen-cdb-fragment-path")
  assert cdb_path, f"Missing Compile Directory Path: {argv}"

  # We can now run the linker and look at the output of some files.
  dependency_file = os.path.join(cdb_path,
                                 os.path.basename(output_file) + ".deps")
  why_extract_file = os.path.join(
      cdb_path,
      os.path.basename(output_file) + ".why_extract")
  argv.append("-fuse-ld=lld")
  argv.append(f"-Wl,--dependency-file={dependency_file}")
  argv.append(f"-Wl,--why-extract={why_extract_file}")
  argv.append("-Wl,--build-id")
  argv.append('-Qunused-arguments')
  run(argv)

  build_id = get_build_id(output_file)
  assert build_id is not None

  output_hash = sha256(output_file)

  with open(_IGNORED_DEPS_PATH) as f:
    ignored_deps = frozenset(json.load(f)["deps"])

  deps = parse_dependency_file(dependency_file, output_file, ignored_deps)
  obj_deps = [dep for dep in deps if dep.endswith(".o")]
  ar_deps = [dep for dep in deps if dep.endswith(".a") and dep != fuzzer_engine]
  archive_deps = []
  for archive in ar_deps:
    res = subprocess.run(["ar", "-t", archive], capture_output=True, check=True)
    archive_deps += [dep.decode() for dep in res.stdout.splitlines()]

  cdb = read_cdb_fragments(cdb_path)
  commands = {}
  for dep in obj_deps:
    print(f"Looking for dep {dep}")
    if dep == fuzzer_engine:
      continue
    dep = os.path.realpath(dep)
    for command in cdb:
      command_path = os.path.realpath(
          os.path.join(command["directory"], command["output"]))
      if command_path == dep:
        commands[dep] = command

    if dep not in commands:
      print(f"{dep} NOT FOUND")

  for archive_dep in archive_deps:
    # We don't have the full path of the archive dep, so we will only look at
    # the basename.
    for command in cdb:
      if os.path.basename(command["output"]) == archive_dep:
        commands[archive_dep] = command

    if archive_dep not in commands:
      print(f"{archive_dep} NOT FOUND")

  linker_commands = {
      "output": output_file,
      "directory": os.getcwd(),
      "deps": obj_deps + archive_deps,
      "args": argv,
      "sha256": output_hash,
      "gnu_build_id": build_id,
      "compile_commands": list(commands.values()),
  }
  run_indexer(build_id, linker_commands)
  linker_commands = json.dumps(linker_commands)
  commands_path = os.path.join(cdb_path, build_id + "_linker_commands.json")
  with open(commands_path, "w") as f:
    f.write(linker_commands)


if __name__ == "__main__":
  main(sys.argv)
