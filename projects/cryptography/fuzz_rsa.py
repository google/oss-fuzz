#!/usr/bin/python3

# Copyright 2026 Google LLC
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
with atheris.instrument_imports():
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa, utils, padding

def TestInput(input_bytes):
    fdp = atheris.FuzzedDataProvider(input_bytes)

    private_key = rsa.generate_private_key(key_size=1024, public_exponent=65537)
    public_key = private_key.public_key()

    data = fdp.ConsumeBytes(20)
    more_data = fdp.ConsumeBytes(20)

    hasher = hashes.Hash(hashes.SHA256())
    hasher.update(data)
    hasher.update(more_data)
    digest = hasher.finalize()

    sig1 = private_key.sign(data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
    sig2 = private_key.sign(digest, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), utils.Prehashed(hashes.SHA256()))

    public_key.verify(sig1, data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
    public_key.verify(sig2, digest, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), utils.Prehashed(hashes.SHA256()))

def main():
    atheris.Setup(sys.argv, TestInput, enable_python_coverage=False)
    atheris.instrument_all()
    atheris.Fuzz()

if __name__ == "__main__":
    main()
