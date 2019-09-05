#!/usr/bin/env python
# Copyright 2019 Google Inc.
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
"""Statically check project for common issues."""

from __future__ import print_function

import itertools
import os
from multiprocessing.pool import ThreadPool
import sys
import yaml


def get_oss_fuzz_root():
  """Get the absolute path of the root of the oss-fuzz checkout."""
  script_path = os.path.realpath(__file__)
  return os.path.abspath(os.path.join(os.path.dirname(script_path), '..'))


def is_project_file(actual_path, expected_filename):
  if os.path.basename(actual_path) != expected_filename:
    return False

  if os.path.basename(
      os.path.dirname(os.path.dirname(actual_path))) != 'projects':
    return False

  return os.path.exists(actual_path)


def check_lib_fuzzing_engine(build_sh_file):
  if not is_project_file(build_sh_file, 'build.sh'):
    return True

  with open(build_sh_file) as build_sh:
    build_sh_lines = build_sh.readlines()
  for line_num, line in enumerate(build_sh_lines):
    uncommented_code = line.split('#')[0]
    if '-lFuzzingEngine' in uncommented_code:
      print('''Error: build.sh contains -lFuzzingEngine on line: {0}.
Please use $LIB_FUZZING_ENGINE.'''.format(line_num))
      return False
  return True


class ProjectYamlChecker:
  def __init__(self, project_yaml_filename):
    self.project_yaml_filename = project_yaml_filename
    with open(project_yaml_filename) as file_handle:
      self.project_yaml = yaml.safe_load(file_handle)

    self.success = True

    self.checks = [self.check_project_yaml_constants,
                   self.check_required_sections,
                   self.check_valid_section_names,
                   self.check_valid_emails]

  def do_checks(self):
    """Do all project.yaml checks. Return True if they pass."""
    if self.is_disabled():
      return True
    for check_function in self.checks:
      check_function()
    return self.success

  def is_disabled(self):
    """Is this project disabled."""
    return self.project_yaml.get('disabled', False)

  def print_error_message(self, message, *args):
    """Print an error message and set self.success to False."""
    self.success = False
    message = message % args
    print('Error in %s: %s' % (self.project_yaml_filename, message))

  def check_project_yaml_constants(self):
    """Check that certain sections only have certain constant values."""
    sections_and_constants = {
        'sanitizers': ['address', 'none', 'memory', 'address'],
        'architectures': ['i386', 'x86_64'],
        'engines': ['afl', 'libfuzzer', 'honggfuzz']
    }
    success = True
    for section, constants in sections_and_constants.items():
      if section not in self.project_yaml:
        continue
      section_contents = self.project_yaml[section]
      for constant in section_contents:
        if constant not in section_contents:
          self.print_error_message('%s not one of %s', constant, constants)

  def check_valid_section_names(self):
    """Check that only valid sections are included."""
    # Note, this list must be updated when we allow new sections.
    valid_section_names = [
        'homepage', 'primary_contact', 'auto_ccs', 'sanitizers',
        'architectures', 'disabled'
    ]
    for name in self.project_yaml:
      if name not in valid_section_names:
        self.print_error_message(
            '%s not a valid section name (%s)', name, valid_section_names)

  def check_required_sections(self):
    """Check that all required sections are present."""
    required_sections = ['primary_contact']
    for section in required_sections:
      if section not in self.project_yaml:
        self.print_error_message(
            'No %s section.', section)


  def check_valid_emails(self):
    """Check that emails are valid looking."""
    for section in ['auto_ccs', 'primay_contact']:
      for email_address in self.project_yaml.get(section, []):
        if not ('@' in email_address and '.' in email_address):
          self.print_error_message('%s is an invalid email address.',
                                   email_address)

def check_project_yaml(project_yaml_filename):
  """Do checks on the project.yaml file."""
  if not is_project_file(project_yaml_filename, 'project.yaml'):
    return True

  checker = ProjectYamlChecker(project_yaml_filename)
  return checker.do_checks()


def do_check(check_func, argument):
  """Run call check_func(argument) and return the result."""
  try:
    return check_func(argument)
  except Exception:
    print(
        'Error doing check: %s() on %s:'
        '\n%s: %s' % (check_func.__name__, argument, e.__class__.__name__, e)
    )
    return False


def do_checks(filenames):
  """Do all checks on |filenames|. Return False if any fail."""
  oss_fuzz_root = get_oss_fuzz_root()
  success = True
  checks = [check_project_yaml, check_lib_fuzzing_engine]
  pool = ThreadPool()
  return all(itertools.starmap(do_check, itertools.product(checks, filenames)))


def main():
  if len(sys.argv) < 2:
    print('Usage: {0} file1 [file2, file3, ...]'.format(sys.argv[0]))
  if not do_checks(sys.argv[1:]):
    exit(1)

if __name__ == '__main__':
  main()
