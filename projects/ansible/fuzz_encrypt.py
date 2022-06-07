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

import atheris
import sys

with atheris.instrument_imports():
    import crypt
    from ansible.plugins.filter.core import get_encrypted_password
    from ansible.utils import encrypt
    from ansible import errors


@atheris.instrument_func
def TestInput(input_bytes):
    if len(input_bytes) < 50:
        return

    fdp = atheris.FuzzedDataProvider(input_bytes)
    try:
        for h in [ "md5", "sha512", "pbkdf2_sha256", "crypt16" ]:
            get_encrypted_password(
                fdp.ConsumeString(20),
                h,
                salt=fdp.ConsumeString(20)
            )
    except errors.AnsibleFilterError as e:
        pass


def main():
    atheris.Setup(sys.argv, TestInput, enable_python_coverage=True)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
