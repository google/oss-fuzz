#!/usr/bin/python3
# Copyright 2022 Google LLC
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
"""Targets: https://github.com/python-ldap/python-ldap/security/advisories/GHSA-r8wq-qrxc-hmcm"""  # pylint: disable=line-too-long

import sys
import atheris
import pysecsan
import ldap.schema

pysecsan.add_hooks()


def test_one_input(data):
  """Fuzzer targetting regex dos in ldap."""
  fdp = atheris.FuzzedDataProvider(data)
  try:
    ldap.schema.split_tokens(fdp.ConsumeUnicodeNoSurrogates(1024))
  except ValueError:
    pass


def main():
  """Set up and start fuzzing."""
  atheris.instrument_all()
  atheris.Setup(sys.argv, test_one_input, enable_python_coverage=True)
  atheris.Fuzz()


if __name__ == '__main__':
  main()
