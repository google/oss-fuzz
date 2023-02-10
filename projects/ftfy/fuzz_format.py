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
    import ftfy.formatting as ftfy
    import ftfy.fixes as fixes

def TestInput(data):
    if len(data) < 1:
        return

    fdp = atheris.FuzzedDataProvider(data)

    ftfy.character_width(chr(fdp.ConsumeIntInRange(1,1114110)))
    ftfy.monospaced_width(fdp.ConsumeUnicodeNoSurrogates(1000))

    choice = fdp.ConsumeIntInRange(1,3)
    if choice == 1:
        ftfy.display_ljust(fdp.ConsumeUnicodeNoSurrogates(1000),fdp.ConsumeIntInRange(1,2000))
    if choice == 2:
        ftfy.display_rjust(fdp.ConsumeUnicodeNoSurrogates(1000),fdp.ConsumeIntInRange(1,2000))
    if choice == 3:
        ftfy.display_center(fdp.ConsumeUnicodeNoSurrogates(1000),fdp.ConsumeIntInRange(1,2000))
    fixes.remove_bom(fdp.ConsumeUnicodeNoSurrogates(1000))
    
def main():
    atheris.Setup(sys.argv, TestInput, enable_python_coverage=True)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
