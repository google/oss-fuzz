#!/usr/bin/env python3
# Copyright 2021 Google LLC
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
"""Helper script to detect if a program harness is stateful based on coverage results."""

import subprocess
import argparse
import tempfile
import shutil
import shlex
import sys
import os
import json
import functools
import traceback
from pathlib import Path
from glob import glob

PROFRAW_SUFFIX = ".%1m.profraw"
PROFRAW_GLOB_SUFFIX = ".*.profraw"
PROFDATA_SUFFIX = ".profdata"


class CmdExecException(Exception):
  pass


class CoverageReportMismatch(Exception):
  pass


def exec_cmd(cmd, **kwargs):
  proc = subprocess.run(
      cmd,
      stdout=subprocess.PIPE,
      stderr=subprocess.STDOUT,
      errors="backslashreplace",
      **kwargs,
  )
  if proc.returncode != 0:
    raise CmdExecException(f"{proc}")
  return proc


def gather_coverage(
    out_dir,
    dumps_dir,
    target_name,
    fuzztest_binary_name,
    shared_libs,
    common_cov_args,
    summary_only,
    dummy_out_dir,
    corpus_dir,
):
  out_dir = Path(out_dir)
  _dumps_dir = Path(dumps_dir)
  target = out_dir / target_name
  with tempfile.TemporaryDirectory() as prof_dir_str:
    prof_dir = Path(prof_dir_str)
    profraw_file = prof_dir / (target_name + PROFRAW_SUFFIX)
    profraw_file_mask = str(prof_dir / (target_name + PROFRAW_GLOB_SUFFIX))
    profdata_file = prof_dir / (target_name + PROFDATA_SUFFIX)

    env = os.environ.copy()
    env["LLVM_PROFILE_FILE"] = profraw_file
    cmd = [
        target,
        "-merge=1",
        "-timeout=100",
        "-rss_limit_mb=16000",
        "-print_final_stats=1",
        "-verbosity=1",
        dummy_out_dir,
        corpus_dir,
    ]
    print("gather coverage cmd:", cmd)
    print(exec_cmd(cmd, timeout=100, env=env).stdout[-1000:])
    dummy_out_files = list(glob(f"{dummy_out_dir}/*"))
    print("minimized corpus files:", len(dummy_out_files))

    profraw_files = list(glob(profraw_file_mask))

    if len(profraw_files) == 0:  # no profile dumps created
      print(f"no profile dumps created, searched: {profraw_file_mask}")
      return 0

    fuzztest_binary_path = out_dir / fuzztest_binary_name

    # TODO seems to usually fail, not sure if that is ok
    exec_cmd(["profraw_update.py", fuzztest_binary_path, "-i", *profraw_files])

    exec_cmd([
        "llvm-profdata",
        "merge",
        "-j=1",
        "-sparse",
        *profraw_files,
        "-o",
        profdata_file,
    ])

    summary_proc = exec_cmd([
        "llvm-cov",
        "export",
        *(["-summary-only"] if summary_only else []),
        f"-instr-profile={profdata_file}",
        f"-object={target_name}",
        *shared_libs,
        *common_cov_args,
    ])

  data = json.loads(summary_proc.stdout)

  return data


def copy_files_indexed(to_dir, files):
  idx = 0
  for cf in files:
    shutil.copy(cf, Path(to_dir) / f"{idx:08}")
    idx += 1


def merge_coverage(cov):
  merged = {}
  while len(cov["data"][0]["files"]) > 0:
    ff = cov["data"][0]["files"].pop()
    filename = ff["filename"]
    assert filename not in merged
    merged[filename] = {
        "count_instantiations": ff["summary"]["instantiations"]["count"],
        "covered_instantiations": ff["summary"]["instantiations"]["covered"],
        "count_branches": ff["summary"]["branches"]["count"],
        "covered_branches": ff["summary"]["branches"]["covered"],
    }

  return merged


def merge_coverage_detailed(cov):
  merged = {}
  while len(cov["data"][0]["files"]) > 0:
    ff = cov["data"][0]["files"].pop()
    # only continue with this file if there are executable segments
    # (code regions that get a execution count in the coverage report)
    if ff["summary"]["branches"]["count"] == 0:
      continue
    filename = ff["filename"]
    assert filename not in merged
    segments = {}
    for seg in ff["segments"]:
      # based on this code: https://github.com/llvm/llvm-project/blob/9b853f63bef20fd1f19ec933667b1f619afc0f1d/llvm/tools/llvm-cov/CoverageExporterJson.cpp#L83
      [line, column, count, has_count, _is_region_entry, _is_gap_region] = seg
      if has_count:
        segments[(line, column)] = count

    merged[filename] = {
        "count_branches": ff["summary"]["branches"]["count"],
        "covered_branches": ff["summary"]["branches"]["covered"],
        "segments": segments,
    }

  return merged


def add_nested(data, keys, value):
  dd = data
  for kk in keys[:-1]:
    dd = dd.setdefault(kk, {})
  dd[keys[-1]] = value


def cmp_coverages(cov1, cov2, detailed):
  is_stateful = False
  if cov1["version"] != cov2["version"]:
    raise CoverageReportMismatch(
        "Version mismatch: {cov1['version']} != {cov2['version']}")

  if cov1["type"] != cov2["type"]:
    raise CoverageReportMismatch(
        "Type mismatch: {cov1['type']} != {cov2['type']}")

  # TODO can that data be longer?
  assert len(cov1["data"]) == 1
  assert len(cov2["data"]) == 1

  mismatches = {"detailed": detailed}

  if detailed:
    merged1 = merge_coverage_detailed(cov1)
    merged2 = merge_coverage_detailed(cov2)
  else:
    merged1 = merge_coverage(cov1)
    merged2 = merge_coverage(cov2)

  if len(merged1.keys() ^ merged2.keys()) > 0:
    print(f"files mismatch: {merged1.keys() ^ merged2.keys()}")
    mismatches = {
        "files": {
            "only_in_cov_1": merged1.keys() - merged2.keys(),
            "only_in_cov_2": merged2.keys() - merged1.keys(),
        }
    }
    is_stateful = True

  for kk in list(merged1.keys() & merged2.keys()):
    m1 = merged1.pop(kk)
    m2 = merged2.pop(kk)

    if detailed:
      (sm1, sm2) = (m1["segments"], m2["segments"])
      sm_locs = sm1.keys() | sm2.keys()
      for loc in sorted(sm_locs):
        count1 = sm1.get(loc, "miss")
        count2 = sm2.get(loc, "miss")
        if count1 != count2:
          # if count1 == 'miss' and count2 == 'miss':
          print(f"{kk}:{loc[0]:5}:{loc[1]:<3} - {count1:5} != {count2:<5}")
          add_nested(
              mismatches,
              ["segments", kk, loc[0], loc[1]],
              (
                  count1,
                  count2,
              ),
          )
          is_stateful = True
    else:
      if m1 != m2:
        print(f"Mismatched coverage for {kk}:\n{m1}\n{m2}")
        add_nested(
            mismatches,
            ["lines", kk],
            {
                "cov1": m1,
                "cov2": m2
            },
        )
        is_stateful = True

  mismatches["is_stateful"] = is_stateful

  return is_stateful, mismatches


def main():
  """Helper script to detect if a program harness is stateful based on coverage results."""
  parser = argparse.ArgumentParser()
  parser.add_argument("--out-dir", required=True)
  parser.add_argument("--dumps-dir", required=True)
  parser.add_argument("--target", required=True)
  parser.add_argument("--corpus-dir", required=True)
  parser.add_argument("--fuzztest-binary-name", required=True)
  parser.add_argument("--shared-libs", required=True)
  parser.add_argument("--common-cov-args", required=True)
  parser.add_argument("--data-path", required=True)
  parser.add_argument("--detailed",
                      action="store_true",
                      help="Enable detailed coverage analysis")

  args = parser.parse_args()

  print("Statefulness Detector")

  print("args:", args)
  print()

  corpus_dir = Path(args.corpus_dir)
  corpus_files = [
      corpus_dir / ff
      for ff in glob("*", root_dir=corpus_dir, recursive=True)
      if (corpus_dir / ff).is_file()
  ]
  print(f"Number of corpus files: {len(corpus_files)} in: {corpus_dir}")

  if args.detailed:
    print("Comparing by execution count per segment")
  else:
    print("Comparing by the summary results")

  # chosen_files = random.sample(corpus_files, 10)
  chosen_files = corpus_files
  dir_cov = functools.partial(
      gather_coverage,
      args.out_dir,
      args.dumps_dir,
      args.target,
      args.fuzztest_binary_name,
      shlex.split(args.shared_libs),
      shlex.split(args.common_cov_args),
      not args.detailed,
  )

  with tempfile.TemporaryDirectory() as partial_corpus_dir:
    copy_files_indexed(partial_corpus_dir, chosen_files)
    with tempfile.TemporaryDirectory() as merged_out_dir:
      cov1 = dir_cov(merged_out_dir, partial_corpus_dir)

  with tempfile.TemporaryDirectory() as partial_corpus_dir:
    copy_files_indexed(partial_corpus_dir, reversed(chosen_files))
    with tempfile.TemporaryDirectory() as merged_out_dir:
      cov2 = dir_cov(merged_out_dir, partial_corpus_dir)

  (is_stateful, data) = cmp_coverages(cov1, cov2, args.detailed)
  if is_stateful:
    print("Target IS stateful.")
    out_path = Path(args.data_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "wt") as f:
      json.dump(data, f)
    return 1
  else:
    print("Target is not stateful.")
    return 0


if __name__ == "__main__":
  try:
    sys.exit(main())
  except Exception as e:
    print(f"Exception: {e}")
    print("Full traceback:")
    print(traceback.format_exc())
    sys.exit(2)
