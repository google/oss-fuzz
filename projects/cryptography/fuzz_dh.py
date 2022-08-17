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
import sys
import atheris
with atheris.instrument_imports():
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import dh
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

def TestInput(input_bytes):
    fdp = atheris.FuzzedDataProvider(input_bytes)

    try:
        parameters = dh.generate_parameters(
            generator=(2 if fdp.ConsumeBool() else 5), 
            key_size=fdp.ConsumeInt(15)
        )
    except ValueError as e:
        if "DH key_size must be at least 512 bits" not in str(e):
            raise e
        else:
            return

    server_private_key = parameters.generate_private_key()
    peer_private_key = parameters.generate_private_key()
    server_derived_shared_key = server_private_key.exchange(peer_private_key.public_key())
    peer_derived_shared_key = peer_private_key.exchange(server_private_key.public_key())

    infobytes = fdp.ConsumeBytes(10)

    server_derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=infobytes,
    ).derive(server_derived_shared_key)

    peer_derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=infobytes,
    ).derive(peer_derived_shared_key)

    assert (server_derived_key == peer_derived_key), "Key Derivation Error!!"

def main():
    atheris.Setup(sys.argv, TestInput, enable_python_coverage=False)
    atheris.instrument_all()
    atheris.Fuzz()

if __name__ == "__main__":
    main()
