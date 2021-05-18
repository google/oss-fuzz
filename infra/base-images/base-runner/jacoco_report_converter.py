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
import sys
import xml.etree.ElementTree as ET


def convert(xml):
  """Turns a JaCoCo XML report into an llvm-cov JSON summary."""
  summary = {
      "type": "oss-fuzz.java.coverage.json.export",
      "version": "1.0.0",
      "data": [{
          "totals": {},
      }],
  }

  root = ET.fromstring(xml)
  totals = {}

  function_counter = root.find("./counter[@type='METHOD']")
  totals["functions"] = make_counter_summary(function_counter)

  line_counter = root.find("./counter[@type='LINE']")
  totals["lines"] = make_counter_summary(line_counter)

  region_counter = root.find("./counter[@type='BRANCH']")
  totals["regions"] = make_counter_summary(region_counter)

  summary["data"][0]["totals"] = totals

  return json.dumps(summary)


def make_counter_summary(counter_element):
  """Turns a JaCoCo <counter> tag into an llvm-cov totals entry."""
  summary = {}
  summary["covered"] = int(counter_element.attrib["covered"])
  summary["notcovered"] = int(counter_element.attrib["missed"])
  summary["count"] = summary["covered"] + summary["notcovered"]
  summary["percent"] = (100.0 * summary["covered"]) / summary["count"]
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


if __name__ == "__main__":
  sys.exit(main())
