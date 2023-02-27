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

import ntlm_auth.compute_hash as compute_hash
import ntlm_auth.compute_keys as compute_keys
from ntlm_auth.constants import SignSealConstants
from ntlm_auth.compute_response import ComputeResponse


def fuzz_hash(data):
  fdp = atheris.FuzzedDataProvider(data)
  compute_hash._lmowfv1(fdp.ConsumeUnicodeNoSurrogates(256))
  compute_hash._ntowfv1(fdp.ConsumeUnicodeNoSurrogates(256))


def fuzz_compute_response(data):
  fdp = atheris.FuzzedDataProvider(data)
  ComputeResponse._get_NTLMv1_response(fdp.ConsumeUnicodeNoSurrogates(256),
                                       fdp.ConsumeBytes(124))
  ComputeResponse._get_NTLM2_response(fdp.ConsumeUnicodeNoSurrogates(256),
                                      fdp.ConsumeBytes(124),
                                      fdp.ConsumeBytes(124))
  ComputeResponse._get_LMv1_response(fdp.ConsumeUnicodeNoSurrogates(256),
                                     fdp.ConsumeBytes(124))
  ComputeResponse._get_LMv2_response(fdp.ConsumeUnicodeNoSurrogates(256),
                                     fdp.ConsumeUnicodeNoSurrogates(256),
                                     fdp.ConsumeUnicodeNoSurrogates(256),
                                     fdp.ConsumeBytes(124),
                                     fdp.ConsumeBytes(124))


def fuzz_compute_keys(data):
  fdp = atheris.FuzzedDataProvider(data)
  try:
    compute_keys._get_exchange_key_ntlm_v1(fdp.ConsumeInt(4),
                                         fdp.ConsumeBytes(124),
                                         fdp.ConsumeBytes(124),
                                         fdp.ConsumeBytes(124),
                                         fdp.ConsumeBytes(124))
  except ValueError:
    pass
  try:
    compute_keys.get_seal_key(fdp.ConsumeInt(4), fdp.ConsumeBytes(124),
                            SignSealConstants.CLIENT_SEALING)
  except ValueError:
    pass


def TestOneInput(data):
  fuzz_hash(data)
  fuzz_compute_response(data)
  fuzz_compute_keys(data)


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
