#!/usr/bin/env python3
#
# Copyright 2023 Google LLC
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
"""Script for generating differential coverage reports.
generate_differential_cov_report.py <profdata-dump-directory> \
<profdata-directory-to-subtract-from-first> <output-directory>
"""
import os
import shutil
import subprocess
import sys


class ProfData:
  """Class representing a profdata file."""

  def __init__(self, text):
    self.function_profs = []
    for function_prof in text.split('\n\n'):
      if not function_prof:
        continue
      self.function_profs.append(FunctionProf(function_prof))

  def to_string(self):
    """Convert back to a string."""
    return '\n'.join(
        [function_prof.to_string() for function_prof in self.function_profs])

  def find_function(self, function, idx=None):
    """Find the same function in this profdata."""
    if idx is not None:
      try:
        possibility = self.function_profs[idx]
        if function.func_hash == possibility.func_hash:
          return possibility
      except IndexError:
        pass
    for function_prof in self.function_profs:
      if function_prof.func_hash == function.func_hash:
        return function_prof
    return None

  def subtract(self, subtrahend):
    """Subtract subtrahend from this profdata."""
    for idx, function_prof in enumerate(self.function_profs):
      subtrahend_function_prof = subtrahend.find_function(function_prof, idx)
      function_prof.subtract(subtrahend_function_prof)


class FunctionProf:
  """Profile of a function."""
  FUNC_HASH_COMMENT_LINE = '# Func Hash:'
  NUM_COUNTERS_COMMENT_LINE = '# Num Counters:'
  COUNTER_VALUES_COMMENT_LINE = '# Counter Values:'

  def __init__(self, text):
    print(text)
    lines = text.splitlines()
    self.function = lines[0]
    assert self.FUNC_HASH_COMMENT_LINE == lines[1]
    self.func_hash = lines[2]
    assert self.NUM_COUNTERS_COMMENT_LINE == lines[3]
    self.num_counters = int(lines[4])
    assert self.COUNTER_VALUES_COMMENT_LINE == lines[5]
    self.counter_values = [1 if int(line) else 0 for line in lines[6:]]

  def to_string(self):
    """Convert back to text."""
    lines = [
        self.function,
        self.FUNC_HASH_COMMENT_LINE,
        self.func_hash,
        self.NUM_COUNTERS_COMMENT_LINE,
        str(self.num_counters),
        self.COUNTER_VALUES_COMMENT_LINE,
    ] + [str(num) for num in self.counter_values]
    return '\n'.join(lines)

  def subtract(self, subtrahend_prof):
    """Subtract this other function from this function."""
    if not subtrahend_prof:
      print(self.function, 'has no subtrahend')
      # Nothing to subtract.
      return
    self.counter_values = [
        max(counter1 - counter2, 0) for counter1, counter2 in zip(
            self.counter_values, subtrahend_prof.counter_values)
    ]


def get_profdata_files(directory):
  """Returns profdata files in |directory|."""
  profdatas = []
  for filename in os.listdir(directory):
    filename = os.path.join(directory, filename)
    if filename.endswith('.profdata'):
      profdatas.append(filename)
  return profdatas


def convert_profdata_to_text(profdata):
  """Convert a profdata binary file to a profdata text file."""
  profdata_text = f'{profdata}.txt'
  if os.path.exists(profdata_text):
    os.remove(profdata_text)
  command = [
      'llvm-profdata', 'merge', '-j=1', '-sparse', profdata, '--text', '-o',
      profdata_text
  ]
  print(command)
  subprocess.run(command, check=True)
  return profdata_text


def convert_text_profdata_to_bin(profdata_text):
  """Convert a profdata text file to a profdata binary file."""
  profdata = profdata_text.replace('.txt', '').replace('.profdata',
                                                       '') + '.profdata'
  print('bin profdata', profdata)
  if os.path.exists(profdata):
    os.remove(profdata)
  command = [
      'llvm-profdata', 'merge', '-j=1', '-sparse', profdata_text, '-o', profdata
  ]
  print(command)
  subprocess.run(command, check=True)
  return profdata


def get_difference(minuend_filename, subtrahend_filename):
  """Subtract subtrahend_filename from minuend_filename."""
  with open(minuend_filename, 'r', encoding='utf-8') as minuend_file:
    print('minuend', minuend_filename)
    minuend = ProfData(minuend_file.read())
  with open(subtrahend_filename, 'r', encoding='utf-8') as subtrahend_file:
    print('subtrahend', subtrahend_filename)
    subtrahend = ProfData(subtrahend_file.read())

  minuend.subtract(subtrahend)
  return minuend


def profdatas_to_objects(profdatas):
  """Get the corresponding objects for each profdata."""
  return [
      os.path.splitext(os.path.basename(profdata))[0] for profdata in profdatas
  ]


def generate_differential_cov_reports(minuend_profdatas, subtrahend_profdatas,
                                      difference_dir):
  """Calculate the differences between all profdatas and generate differential
  coverage reports."""
  profdata_objects = profdatas_to_objects(minuend_profdatas)
  real_profdata_objects = [
      binobject for binobject in profdata_objects if binobject != 'merged'
  ]
  for minuend, subtrahend, binobject in zip(minuend_profdatas,
                                            subtrahend_profdatas,
                                            profdata_objects):
    minuend_text = convert_profdata_to_text(minuend)
    subtrahend_text = convert_profdata_to_text(subtrahend)
    difference = get_difference(minuend_text, subtrahend_text)
    basename = os.path.basename(minuend_text)
    difference_text = os.path.join(difference_dir, basename)
    with open(difference_text, 'w', encoding='utf-8') as file_handle:
      file_handle.write(difference.to_string())
    difference_profdata = convert_text_profdata_to_bin(difference_text)
    if not difference_profdata.endswith('merged.profdata'):
      generate_html_report(difference_profdata, [binobject],
                           os.path.join(difference_dir, binobject))
    else:
      generate_html_report(difference_profdata, real_profdata_objects,
                           os.path.join(difference_dir, 'merged'))


def generate_html_report(profdata, objects, directory):
  """Generate an HTML coverage report."""
  # TODO(metzman): Deal with shared libs.
  html_dir = os.path.join(directory, 'reports')
  if os.path.exists(html_dir):
    os.remove(html_dir)
  os.makedirs(html_dir)
  out_dir = os.getenv('OUT', '/out')
  command = [
      'llvm-cov', 'show', f'-path-equivalence=/,{out_dir}', '-format=html',
      '-Xdemangler', 'rcfilt', f'-instr-profile={profdata}'
  ]

  objects = [os.path.join(out_dir, binobject) for binobject in objects]
  command += objects + ['-o', html_dir]
  print(' '.join(command))
  subprocess.run(command, check=True)


def main():
  """Generate differential coverage reports."""
  if len(sys.argv) != 4:
    print(
        f'Usage: {sys.argv[0]} <minuend_dir> <subtrahend_dir> <difference_dir>')
  minuend_dir = sys.argv[1]
  subtrahend_dir = sys.argv[2]
  difference_dir = sys.argv[3]
  if os.path.exists(difference_dir):
    shutil.rmtree(difference_dir)
  os.makedirs(difference_dir, exist_ok=True)
  minuend_profdatas = get_profdata_files(minuend_dir)
  subtrahend_profdatas = get_profdata_files(subtrahend_dir)
  generate_differential_cov_reports(minuend_profdatas, subtrahend_profdatas,
                                    difference_dir)


if __name__ == '__main__':
  main()
