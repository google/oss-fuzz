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
#
################################################################################

import sys
import atheris
import io

import toml
from toml import ordered as toml_ordered

def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    # Pick from a random set of decoders
    DECODERS = [
        None,
        toml_ordered.TomlOrderedDecoder(),
        toml.TomlPreserveCommentDecoder()
    ]

    try:
        f = io.StringIO(fdp.ConsumeString(sys.maxsize))
        result = toml.decoder.load(f, decoder=fdp.PickValueInList(DECODERS))
    except (toml.TomlDecodeError, IndexError) as e:
        if isinstance(e, IndexError):
            if "IndexError: list index out of range" in str(e) or "IndexError: string index out of range" in str(e):
                pass
            else:
                raise e
        pass


def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
