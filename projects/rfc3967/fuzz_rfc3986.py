#!/usr/bin/python3
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
import sys
import atheris

import rfc3986


def fuzz_parseresult(data):
  fdp = atheris.FuzzedDataProvider(data)
  try:
    rfc3986.parseresult.ParseResult.from_string(
        fdp.ConsumeUnicodeNoSurrogates(256))
  except (rfc3986.exceptions.RFC3986Exception):
    pass
  try:
    rfc3986.parseresult.ParseResultBytes.from_string(
        fdp.ConsumeUnicodeNoSurrogates(256))
  except (rfc3986.exceptions.RFC3986Exception):
    pass


def fuzz_normalizers(data):
  fdp = atheris.FuzzedDataProvider(data)
  rfc3986.normalizers.normalize_host(fdp.ConsumeUnicodeNoSurrogates(256))
  rfc3986.normalizers.normalize_percent_characters(
      fdp.ConsumeUnicodeNoSurrogates(256))
  rfc3986.normalizers.normalize_scheme(fdp.ConsumeUnicodeNoSurrogates(256))


def fuzz_uri(data):
  fdp = atheris.FuzzedDataProvider(data)
  uri = rfc3986.uri.URIReference.from_string(
      fdp.ConsumeUnicodeNoSurrogates(256))
  uri.is_valid()
  uri.is_absolute()


def fuzz_iri(data):
  fdp = atheris.FuzzedDataProvider(data)
  iri_ref = rfc3986.IRIReference.from_string(
      fdp.ConsumeUnicodeNoSurrogates(256))


def fuzz_api(data):
  fdp = atheris.FuzzedDataProvider(data)
  rfc3986.api.uri_reference(fdp.ConsumeUnicodeNoSurrogates(256))
  rfc3986.api.iri_reference(fdp.ConsumeUnicodeNoSurrogates(256))
  rfc3986.api.is_valid_uri(fdp.ConsumeUnicodeNoSurrogates(256))
  rfc3986.api.normalize_uri(fdp.ConsumeUnicodeNoSurrogates(256))
  rfc3986.api.urlparse(fdp.ConsumeUnicodeNoSurrogates(256))


def fuzz_validators(data):
  fdp = atheris.FuzzedDataProvider(data)
  uri = rfc3986.uri.URIReference.from_string(
      fdp.ConsumeUnicodeNoSurrogates(256))
  if uri.is_valid():
    validator = rfc3986.validators.Validator().forbid_use_of_password()
    try:
      validator.validate(uri)
    except rfc3986.eceptions.RFC3986Exception:
      pass

    validator2 = rfc3986.validators.Validator()
    try:
      validator2.validate(uri)
    except rfc3986.eceptions.RFC3986Exception:
      pass

    validator3 = rfc3986.validators.Validator()
    validator3.allow_schemes(fdp.ConsumeUnicodeNoSurrogates(24))
    validator3.allow_hosts(fdp.ConsumeUnicodeNoSurrogates(24))
    validator3.allow_ports(str(fdp.ConsumeIntInRange(1, 65000)))
    try:
      validator3.require_presence_of(fdp.ConsumeUnicodeNoSurrogates(8))
    except ValueError:
      pass
    try:
      validator3.check_validity_of(fdp.ConsumeUnicodeNoSurrogates(24))
    except ValueError:
      pass
    try:
      validator3.validate(uri)
    except rfc3986.exceptions.RFC3986Exception:
      pass


def TestOneInput(data):
  fuzz_parseresult(data)
  fuzz_normalizers(data)
  fuzz_uri(data)
  fuzz_iri(data)
  fuzz_api(data)
  fuzz_validators(data)


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
