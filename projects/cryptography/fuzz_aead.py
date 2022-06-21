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
    import cryptography.hazmat.primitives.ciphers.aead as aead

def TestInput(input_bytes):
    if len(input_bytes) < 12:
        return

    fdp = atheris.FuzzedDataProvider(input_bytes)

    choice = fdp.ConsumeIntInRange(1,4)

    if choice == 1:
        cipher = aead.ChaCha20Poly1305(aead.ChaCha20Poly1305.generate_key())
    if choice == 2:
        cipher = aead.AESGCM(aead.AESGCM.generate_key(bit_length=128))
    if choice == 3:
        cipher = aead.AESOCB3(aead.AESOCB3.generate_key(bit_length=128))
    if choice == 4:
        cipher = aead.AESCCM(aead.AESCCM.generate_key(bit_length=128))
   
    msg = fdp.ConsumeBytes(32)
    authentext =  fdp.ConsumeBytes(32)
    nonce = fdp.ConsumeBytes(12)
   
    if len(nonce) < 12:
        return

    ciphertext = cipher.encrypt(nonce, msg, authentext)
    plaintext = cipher.decrypt(nonce, ciphertext, authentext)

    assert (plaintext == msg), "Encryption/Decrption error!"

def main():
    atheris.Setup(sys.argv, TestInput, enable_python_coverage=False)
    atheris.instrument_all()
    atheris.Fuzz()

if __name__ == "__main__":
   main()
