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

import os
import sys
import atheris
from underscore import _


def TestOneInput(data):
    with open("tmp.f", "wb") as f:
        f.write(data)

    # Only continue if the file exists.
    if os.path.isfile("tmp.f"):
        try:
            # Call underscore
            _("tmp.f", "dst.f")
        except (SyntaxError, UnicodeDecodeError) as e:
            pass
        except ValueError as e2:
            if "cannot contain null" in str(e2):
                pass
            else:
                raise e2
        except KeyError:
            # This is added because the fuzzer quickly runs into it, and I think
            # the reason is that not all python AST types have been added AFAIK.
            # As such, it's an issue by design.
            pass
        os.remove("tmp.f")


def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
