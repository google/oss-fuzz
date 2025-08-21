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

"""Compiler Wrapper.

This is copied into the OSS-Fuzz container image and run there as part of the
instrumentation process.
"""

from collections.abc import MutableSequence, Sequence
import dataclasses
import hashlib
import json
import os
from pathlib import Path  # pylint: disable=g-importing-member
import shlex
import shutil
import subprocess
import sys
import time
from typing import Any, Iterable, Set

import dwarf_info
import index_build

_LLVM_READELF_PATH = "/usr/local/bin/llvm-readelf"
_INDEXER_PATH = "/opt/indexer/indexer"
_IGNORED_DEPS_PATH = os.path.join(
    os.path.dirname(_INDEXER_PATH), "ignored_deps.json"
)

_INTERNAL_PATHS = ("/src/llvm-project/",)

# When we notice a project using these flags,
# we should figure out how to handle them.
_DISALLOWED_CLANG_FLAGS = (
    "-fdebug-compilation-dir=",
    "-fdebug-prefix-map=",
    "-ffile-compilation-dir=",
    "-ffile-prefix-map=",
)

SRC = Path(os.getenv("SRC", "/src"))
# On OSS-Fuzz build infra, $OUT is not /out.
OUT = Path(os.getenv("OUT", "/out"))
INDEXES_PATH = Path(os.getenv("INDEXES_PATH", "/indexes"))
FUZZER_ENGINE = os.getenv("LIB_FUZZING_ENGINE", "/usr/lib/libFuzzingEngine.a")


def rewrite_argv0(argv: Sequence[str]) -> list[str]:
  """Rewrite argv[0] to point to the real clang location."""
  # We do this because we've set PATH to our wrapper.
  rewritten = [os.path.join("/usr/local/bin/", os.path.basename(argv[0]))]
  rewritten.extend(argv[1:])
  return rewritten


def execute(argv: Sequence[str]) -> None:
  argv = rewrite_argv0(argv)
  print("About to execute...", argv)
  os.execv(argv[0], tuple(argv))


def run(argv: Sequence[str]) -> None:
  argv = rewrite_argv0(argv)
  print("About to run...", argv)
  ret = subprocess.run(argv, check=False)
  if ret.returncode != 0:
    sys.exit(ret.returncode)


def sha256(file: Path) -> str:
  hash_value = hashlib.sha256()
  with open(file, "rb") as f:
    # We can't use hashlib.file_digest here because OSS-Fuzz is still on
    # Python 3.10.
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


def get_build_id(elf_file: Path) -> str | None:
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
          elf_file.as_posix(),
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


def remove_flag_if_present(argv: Iterable[str], flag: str) -> list[str]:
  return [arg for arg in argv if arg != flag]


def remove_flag_and_value(argv: list[str], flag: str) -> list[str] | None:
  """Removes a flag and its value (as a separate token, --a=b not supported.)"""
  for i in range(len(argv) - 1):
    if argv[i] == flag:
      return argv[:i] + argv[i + 2 :]
  return argv


def parse_dependency_file(
    file_path: Path, output_file: Path, ignored_deps: frozenset[str]
) -> Sequence[str]:
  """Parses the dependency file generated by the linker."""
  output_file = output_file.resolve()
  with file_path.open("r") as f:
    lines = [line.strip() for line in f]

  # The first line should have the format "/path/to/file: \"
  # Make sure the binary name matches.
  if output_file.name != Path(lines[0].split(":")[0].strip()).name:
    raise RuntimeError(
        f"dependency file has invalid first line: {lines[0]}. "
        f"Expected to see {output_file.name}."
    )

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


def files_by_creation_time(folder_path: Path) -> Sequence[Path]:
  files = [path for path in folder_path.iterdir() if path.is_file()]
  files.sort(key=os.path.getctime)
  return files


def read_cdb_fragments(cdb_path: Path) -> Any:
  """Iterates through the CDB fragments to reconstruct the compile commands."""
  files = files_by_creation_time(cdb_path)
  contents = []
  for file in files:
    # Don't read previously generated linker commands files.
    if file.name.endswith("_linker_commands.json"):
      continue
    if not file.name.endswith(".json"):
      continue

    data = ""
    num_retries = 3
    for i in range(num_retries):
      with file.open("rt") as f:
        data = f.read()
        if data.endswith(",\n"):
          contents.append(data[:-2])
          break

      if i < num_retries - 1:
        print(
            f"WARNING: CDB fragment {file} appears to be invalid: {data}, "
            f"sleeping for 2^{i+1} seconds before retrying.",
            file=sys.stderr,
        )
        time.sleep(2 ** (i + 1))
    else:
      error = f"CDB fragment {file} is invalid even after retries: {data}"
      if "test.c" in file.name or "conftest.c" in file.name:
        # Some build systems seem to have a weird issue where the autotools
        # generated `test.c` or `conftest.c` for testing compilers doesn't
        # result in valid cdb fragments.
        print(f"WARNING: {error}", file=sys.stderr)
      else:
        raise RuntimeError(error)

  contents = ",\n".join(contents)
  contents = "[" + contents + "]"
  return json.loads(contents)


def run_indexer(build_id: str, linker_commands: dict[str, Any]):
  """Run the indexer."""
  # Use a build-specific compile commands directory, since there could be
  # parallel linking happening at the same time.
  compile_commands_dir = INDEXES_PATH / f"compile_commands_{build_id}"
  try:
    compile_commands_dir.mkdir(exist_ok=False)
  except FileExistsError:
    # Somehow we've already seen this link command, don't try to redo the
    # indexing.
    # TODO: check if this is the safest behaviour.
    print(
        f"WARNING: Compile commands directory {compile_commands_dir} "
        "already created.",
        file=sys.stderr,
    )
    return

  index_dir = INDEXES_PATH / build_id
  if index_dir.exists():
    # A previous indexer already ran for the same build ID.  Clear the directory
    # so we can re-run the indexer, otherwise we might run into various issues
    # (e.g. the indexer doesn't like it when source files already exist).
    shutil.rmtree(index_dir)

  index_dir.mkdir()

  with (compile_commands_dir / "compile_commands.json").open("wt") as f:
    json.dump(linker_commands["compile_commands"], f, indent=2)

  with (compile_commands_dir / "full_compile_commands.json").open("wt") as f:
    json.dump(linker_commands["full_compile_commands"], f, indent=2)

  cmd = [
      _INDEXER_PATH,
      "--build_dir",
      compile_commands_dir,
      "--index_dir",
      index_dir.as_posix(),
      "--source_dir",
      SRC.as_posix(),
  ]
  result = subprocess.run(cmd, check=False, capture_output=True)
  if result.returncode != 0:
    raise RuntimeError(
        "Running indexer failed\n"
        f"stdout:\n```\n{result.stdout.decode()}\n```\n"
        f"stderr:\n```\n{result.stderr.decode()}\n```\n"
    )


def check_fuzzing_engine_and_fix_argv(argv: MutableSequence[str]) -> bool:
  """Check if this command is linking in a fuzzing engine."""
  # Also fix up incorrect link flags so we link in the correct fuzzing
  # engine.
  fuzzing_engine_in_argv = False
  idx = 0
  for arg in argv[:]:
    if arg == "-fsanitize=fuzzer":
      argv[idx] = "-lFuzzingEngine"
      fuzzing_engine_in_argv = True
    elif arg == "-fsanitize=fuzzer-no-link":
      argv.remove("-fsanitize=fuzzer-no-link")
      idx -= 1
    elif arg.startswith("-fsanitize="):
      # This could be -fsanitize=address,fuzzer.
      sanitize_vals = arg.split("=")[1].split(",")
      if "fuzzer" in sanitize_vals:
        sanitize_vals.remove("fuzzer")
        arg = "-fsanitize=" + ",".join(sanitize_vals)
        fuzzing_engine_in_argv = True
      elif "fuzzer-no-link" in sanitize_vals:
        sanitize_vals.remove("fuzzer-no-link")
        arg = "-fsanitize=" + ",".join(sanitize_vals)

      argv[idx] = arg

      if fuzzing_engine_in_argv:
        idx += 1
        argv.insert(idx, "-lFuzzingEngine")

    idx += 1

    if "libFuzzingEngine.a" in arg or "-lFuzzingEngine" in arg:
      fuzzing_engine_in_argv = True

  return fuzzing_engine_in_argv


def _has_disallowed_clang_flags(argv: Sequence[str]) -> bool:
  """Checks if the command line arguments contain disallowed flags."""
  return any(arg.startswith(_DISALLOWED_CLANG_FLAGS) for arg in argv)


@dataclasses.dataclass(frozen=True)
class FilteredCompileCommands:
  filtered_compile_commands: Sequence[dict[str, str]]
  unused_cu_paths: Set[Path]
  unused_cc_paths: Set[Path]


def _filter_compile_commands(
    elf_path: Path, compile_commands: Sequence[dict[str, str]]
) -> FilteredCompileCommands:
  """Extracts compile commands from the DWARF information of an ELF file.

  Args:
    elf_path: The path to the ELF file.
    compile_commands: The compile commands to filter.

  Returns:
    The filtered compile commands.
  """
  compilation_units = dwarf_info.get_all_compilation_units(elf_path)
  cu_paths = set([Path(cu.compdir) / cu.name for cu in compilation_units])
  used_cu_paths = set()
  filtered_compile_commands = []
  unused_cc_paths = set()

  for compile_command in compile_commands:
    cc_path = Path(compile_command["directory"]) / compile_command["file"]
    if cc_path in cu_paths:
      filtered_compile_commands.append(compile_command)
      used_cu_paths.add(cc_path)
    else:
      unused_cc_paths.add(cc_path)

  unused_cu_paths = cu_paths - used_cu_paths

  return FilteredCompileCommands(
      filtered_compile_commands=filtered_compile_commands,
      unused_cu_paths=unused_cu_paths,
      unused_cc_paths=unused_cc_paths,
  )


def _write_filter_log(
    filter_log_file: Path,
    filtered_compile_commands: FilteredCompileCommands,
) -> None:
  """Writes the filter log file."""
  with open(filter_log_file, "wt") as f:
    f.write("The following files were not used in the final binary:\n")
    for cc_path in sorted(filtered_compile_commands.unused_cc_paths):
      f.write(f"\t{cc_path}\n")

    f.write(
        "The following compilation units were not matched with any compile"
        " commands:\n"
    )
    for cu_path in sorted(filtered_compile_commands.unused_cu_paths):
      if cu_path.as_posix().startswith(_INTERNAL_PATHS):
        continue
      f.write(f"\t{cu_path}\n")


def expand_rsp_file(argv: Sequence[str]) -> list[str]:
  # https://llvm.org/docs/CommandLine.html#response-files
  expanded = []
  for arg in argv:
    if arg.startswith("@"):
      with open(arg[1:], "r") as f:
        expanded_args = shlex.split(f.read())
      expanded.extend(expanded_args)
    else:
      expanded.append(arg)

  return expanded


def force_optimization_flag(argv: Sequence[str]) -> list[str]:
  """Forces -O0 in the given argument list."""
  args = []
  for arg in argv:
    if arg.startswith("-O") and arg != "-O0":
      arg = "-O0"

    args.append(arg)

  return args


def remove_invalid_coverage_flags(argv: Sequence[str]) -> list[str]:
  """Removes invalid coverage flags from the given argument list."""
  args = []
  for arg in argv:
    if (
        arg.startswith("-fsanitize-coverage=")
        and index_build.EXPECTED_COVERAGE_FLAGS != arg
    ):
      continue

    args.append(arg)

  return args


def main(argv: list[str]) -> None:
  argv = expand_rsp_file(argv)
  argv = remove_flag_if_present(argv, "-gline-tables-only")
  argv = force_optimization_flag(argv)
  argv = remove_invalid_coverage_flags(argv)

  if _has_disallowed_clang_flags(argv):
    raise ValueError("Disallowed clang flags found, aborting.")

  if "-E" in argv:
    # Preprocessor-only invocation.
    modified_argv = remove_flag_and_value(argv, "-gen-cdb-fragment-path")
    execute(modified_argv)

  fuzzing_engine_in_argv = check_fuzzing_engine_and_fix_argv(argv)
  indexer_targets: list[str] = [
      t for t in os.getenv("INDEXER_TARGETS", "").split(",") if t
  ]

  # If we are linking, collect the relevant flags and dependencies.
  output_file = get_flag_value(argv, "-o")
  if not output_file:
    execute(argv)  # Missing output file

  output_file = Path(output_file)

  if output_file.name.endswith(".o"):
    execute(argv)  # Not a real linker command

  if indexer_targets:
    if output_file.name not in indexer_targets:
      # Not a relevant linker command
      print(f"Not indexing as {output_file} is not in the allowlist")
      execute(argv)
  elif not fuzzing_engine_in_argv:
    # Not a fuzz target.
    execute(argv)

  print(f"Linking {argv}")

  cdb_path = get_flag_value(argv, "-gen-cdb-fragment-path")
  assert cdb_path, f"Missing Compile Directory Path: {argv}"

  cdb_path = Path(cdb_path)

  # We can now run the linker and look at the output of some files.
  dependency_file = (cdb_path / output_file.name).with_suffix(".deps")
  why_extract_file = (cdb_path / output_file.name).with_suffix(".why_extract")
  argv.append("-fuse-ld=lld")
  argv.append(f"-Wl,--dependency-file={dependency_file}")
  argv.append(f"-Wl,--why-extract={why_extract_file}")
  argv.append("-Wl,--build-id")
  # We force lld, but it doesn't include this dir by default.
  argv.append("-L/usr/local/lib")
  argv.append("-Qunused-arguments")
  run(argv)

  build_id = get_build_id(output_file)
  assert build_id is not None

  output_hash = sha256(output_file)

  with open(_IGNORED_DEPS_PATH) as f:
    ignored_deps = frozenset(json.load(f)["deps"])

  deps = parse_dependency_file(dependency_file, output_file, ignored_deps)
  obj_deps = [dep for dep in deps if dep.endswith(".o")]
  ar_deps = [dep for dep in deps if dep.endswith(".a") and dep != FUZZER_ENGINE]
  archive_deps = []
  for archive in ar_deps:
    res = subprocess.run(["ar", "-t", archive], capture_output=True, check=True)
    archive_deps += [dep.decode() for dep in res.stdout.splitlines()]

  # We only care about the compile commands that emitted an output file.
  full_compile_commands = [
      cc for cc in read_cdb_fragments(cdb_path) if "output" in cc
  ]

  # Discard compile commands that didn't end up in the final binary.
  filtered_compile_commands = _filter_compile_commands(
      output_file, full_compile_commands
  )

  linker_commands = {
      "output": output_file.as_posix(),
      "directory": os.getcwd(),
      "deps": obj_deps + archive_deps,
      "args": argv,
      "sha256": output_hash,
      "gnu_build_id": build_id,
      "compile_commands": filtered_compile_commands.filtered_compile_commands,
      "full_compile_commands": full_compile_commands,
  }

  filter_log_file = Path(cdb_path) / f"{build_id}_filter_log.txt"
  _write_filter_log(filter_log_file, filtered_compile_commands)

  if not os.getenv("INDEXER_BINARIES_ONLY"):
    run_indexer(build_id, linker_commands)

  linker_commands = json.dumps(linker_commands)
  commands_path = Path(cdb_path) / f"{build_id}_linker_commands.json"
  commands_path.write_text(linker_commands)


if __name__ == "__main__":
  main(sys.argv)
