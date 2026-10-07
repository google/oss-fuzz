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
import validators


def TestOneInput(data):
  fdp = atheris.FuzzedDataProvider(data)
  targets = [
      validators.uuid,
      validators.url,
      validators.slug,
      validators.mac_address,
      validators.ipv4,
      validators.ipv6,
      validators.iban,
      validators.md5,
      validators.sha1,
      validators.sha224,
      validators.sha256,
      validators.sha512,
      validators.iban,
      validators.email,
      validators.domain,
      validators.card_number,
      validators.visa,
      validators.mastercard,
      validators.amex,
      validators.unionpay,
      validators.diners,
      validators.jcb,
      validators.discover,
      validators.btc_address,
      validators.fi_business_id,
  ]

  try:
    target = fdp.PickValueInList(targets)
    target(fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 1024)))
  except validators.ValidationFailure:
    pass

  try:
    validators.length(fdp.ConsumeUnicodeNoSurrogates(
        fdp.ConsumeIntInRange(0, 1024)),
                      min_val=fdp.ConsumeIntInRange(1, 100),
                      max_val=fdp.ConsumeIntInRange(1, 100))
  except (validators.ValidationFailure, TypeError, AssertionError):
    # Thrown by the functions.
    pass

  try:
    validators.fi_ssn(
        fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 1024)),
        fdp.ConsumeBool())
  except validators.ValidationFailure:
    pass


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
