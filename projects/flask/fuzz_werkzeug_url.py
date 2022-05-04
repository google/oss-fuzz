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
    import werkzeug


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    original = fdp.ConsumeUnicode(100)
    try:
        werkzeug.urls.url_fix(original)
    except UnicodeEncodeError as e2:
        return
    except ValueError as e:
        if not "IPv6" in str(e):
            raise e

    try:
        werkzeug.urls.url_join(
            fdp.ConsumeUnicode(30),
            fdp.ConsumeUnicode(30)
        )
    except UnicodeEncodeError as e2:
        return
    except ValueError as e:
        if not "IPv6" in str(e):
            raise e

    try:
        werkzeug.urls.url_parse(fdp.ConsumeUnicode(30))
    except UnicodeEncodeError as e2:
        return
    except ValueError as e:
        if not "IPv6" in str(e):
            raise e

    try:
        werkzeug.urls.iri_to_uri(fdp.ConsumeUnicode(30))
    except UnicodeEncodeError as e2:
        return
    except ValueError as e:
        if not "IPv6" in str(e):
            raise e

    try:
        werkzeug.urls.url_decode(fdp.ConsumeUnicode(30))
    except UnicodeEncodeError as e2:
        return
    except ValueError as e:
        if not "IPv6" in str(e):
            raise e
    return


def main():
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
