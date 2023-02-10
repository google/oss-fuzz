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
#
################################################################################

import sys
import atheris
from asn1crypto import parser

def TestOneInput(data):
    try:
        parser.parse(data)
    except (ValueError, TypeError) as e:
        # Raises ValueError and TypeError:
        # https://github.com/wbond/asn1crypto/blob/b5f03e6f9797c691a3b812a5bb1acade3a1f4eeb/asn1crypto/parser.py#L91-L92
        pass


def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
