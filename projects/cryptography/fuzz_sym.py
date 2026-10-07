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
import base64
import atheris
with atheris.instrument_imports():
     from cryptography.fernet import Fernet
     from cryptography.hazmat.primitives import hashes
     from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def TestInput(input_bytes):
    fdp = atheris.FuzzedDataProvider(input_bytes)
    plaintext = fdp.ConsumeBytes(32)

    key = Fernet(Fernet.generate_key())
    token = key.encrypt(plaintext)
    text = key.decrypt(token)
    assert (plaintext == text), "Encryption/Decrption error!"

    password = fdp.ConsumeBytes(8)
    salt = fdp.ConsumeBytes(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=1,
    )
    key = Fernet(base64.urlsafe_b64encode(kdf.derive(password)))
    token = key.encrypt(plaintext)
    text = key.decrypt(token)
    assert (plaintext == text), "Encryption/Decrption error!"

def main():
    atheris.Setup(sys.argv, TestInput, enable_python_coverage=False)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
