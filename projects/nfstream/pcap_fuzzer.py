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
    import io
    from nfstream import NFStreamer


def TestOneInput(input_bytes):
    with open('fuzz_one_input.pcap', 'wb') as w:
        # Save it as binary file with .pcap extension
        w.write(io.BytesIO(input_bytes).read())
    try:
        for _ in NFStreamer(source="fuzz_one_input.pcap"):
            pass
    except (ValueError, TypeError):
        pass


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
