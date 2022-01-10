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
"""Helper script for creating an llvm-cov style JSON summary from a JaCoCo XML
report."""
import json
import os
import sys
import xml.etree.ElementTree as ET


def convert(xml):
  """Turns a JaCoCo XML report into an llvm-cov JSON summary."""
  summary = {
      'type': 'oss-fuzz.java.coverage.json.export',
      'version': '1.0.0',
      'data': [{
          'totals': {},
          'files': [],
      }],
  }

  report = ET.fromstring(xml)
  totals = make_element_summary(report)
  summary['data'][0]['totals'] = totals

  # Since Java compilation does not track source file location, we match
  # coverage info to source files via the full class name, e.g. we search for
  # a path in /out/src ending in foo/bar/Baz.java for the class foo.bar.Baz.
  # Under the assumptions that a given project only ever contains a single
  # version of a class and that no class name appears as a suffix of another
  # class name, we can assign coverage info to every source file matched in that
  # way.
  src_files = list_src_files()

  for class_element in report.findall('./package/class'):
    class_name = class_element.attrib['name']
    package_name = os.path.dirname(class_name)
    if 'sourcefilename' not in class_element.attrib:
      continue
    basename = class_element.attrib['sourcefilename']
    # This path is 'foo/Bar.java' for the class element
    # <class name="foo/Bar" sourcefilename="Bar.java">.
    canonical_path = os.path.join(package_name, basename)

    class_summary = make_element_summary(class_element)
    src_files = relative_to_src_path(src_files, canonical_path)
    for src_file in src_files:
      summary['data'][0]['files'].append({
          'filename': src_file,
          'summary': class_summary,
      })

  return json.dumps(summary)


def list_src_files():
  """Returns a map from basename to full path for all files in $OUT/$SRC."""
  filename_to_paths = {}
  out_path = os.environ['OUT'] + '/'
  src_path = os.environ['SRC']
  src_in_out = out_path + src_path
  for dirpath, _, filenames in os.walk(src_in_out):
    for filename in filenames:
      full_path = dirpath + '/' + filename
      # Map /out//src/... to /src/...
      src_path = full_path[len(out_path):]
      filename_to_paths.setdefault(filename, []).append(src_path)
  return filename_to_paths


def relative_to_src_path(src_files, canonical_path):
  """Returns all paths in src_files ending in canonical_path."""
  basename = os.path.basename(canonical_path)
  if basename not in src_files:
    return []
  candidate_paths = src_files[basename]
  return [
      path for path in candidate_paths if path.endswith("/" + canonical_path)
  ]


def make_element_summary(element):
  """Returns a coverage summary for an element in the XML report."""
  summary = {}

  function_counter = element.find('./counter[@type=\'METHOD\']')
  summary['functions'] = make_counter_summary(function_counter)

  line_counter = element.find('./counter[@type=\'LINE\']')
  summary['lines'] = make_counter_summary(line_counter)

  # JaCoCo tracks branch coverage, which counts the covered control-flow edges
  # between llvm-cov's regions instead of the covered regions themselves. For
  # non-trivial code parts, the difference is usually negligible. However, if
  # all methods of a class consist of a single region only (no branches),
  # JaCoCo does not report any branch coverage even if there is instruction
  # coverage. Since this would give incorrect results for CI Fuzz purposes, we
  # increase the regions counter by 1 if there is any amount of instruction
  # coverage.
  instruction_counter = element.find('./counter[@type=\'INSTRUCTION\']')
  has_some_coverage = instruction_counter is not None and int(
      instruction_counter.attrib["covered"]) > 0
  branch_covered_adjustment = 1 if has_some_coverage else 0
  region_counter = element.find('./counter[@type=\'BRANCH\']')
  summary['regions'] = make_counter_summary(
      region_counter, covered_adjustment=branch_covered_adjustment)

  return summary


def make_counter_summary(counter_element, covered_adjustment=0):
  """Turns a JaCoCo <counter> element into an llvm-cov totals entry."""
  summary = {}
  covered = covered_adjustment
  missed = 0
  if counter_element is not None:
    covered += int(counter_element.attrib['covered'])
    missed += int(counter_element.attrib['missed'])
  summary['covered'] = covered
  summary['notcovered'] = missed
  summary['count'] = summary['covered'] + summary['notcovered']
  if summary['count'] != 0:
    summary['percent'] = (100.0 * summary['covered']) / summary['count']
  else:
    summary['percent'] = 0
  return summary


def main():
  """Produces an llvm-cov style JSON summary from a JaCoCo XML report."""
  if len(sys.argv) != 3:
    sys.stderr.write('Usage: %s <path_to_jacoco_xml> <out_path_json>\n' %
                     sys.argv[0])
    return 1

  with open(sys.argv[1], 'r') as xml_file:
    xml_report = xml_file.read()
  json_summary = convert(xml_report)
  with open(sys.argv[2], 'w') as json_file:
    json_file.write(json_summary)

  return 0


if __name__ == '__main__':
  sys.exit(main())
