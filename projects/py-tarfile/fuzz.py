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

import tarfile
import io
import sys
import atheris

@atheris.instrument_func
def test_one_input(data):
    try:
        # Use the data as an in-memory tar file
        with tarfile.open(fileobj=io.BytesIO(data), mode='r') as tar:
            # Try to list the contents
            tar.getnames()
    except tarfile.TarError:
        pass
    except EOFError:
        pass
    except Exception as e:
        raise e

def main():
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
