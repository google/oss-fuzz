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

#!/usr/bin/env python3
import sys
import atheris

@atheris.instrument_func
def test_notebook_cell(data):
    try:
        exec(data.decode('utf-8', errors='ignore'))
    except:
        pass

def main():
    atheris.Setup(sys.argv, test_notebook_cell)
    atheris.Fuzz()

if __name__ == '__main__':
    main()
