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
import traceback

with atheris.instrument_imports():
    import jinja2

def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    original = fdp.ConsumeString(sys.maxsize)

    # Hit the parser
    env = jinja2.Environment()
    try:
        v1 = env.from_string(original)
        v1.render()
    except (jinja2.TemplateSyntaxError, jinja2.UndefinedError, RecursionError, MemoryError) as e:
        return
    except Exception as e2:
        # avoid raising anything that is raise by jinjas "handle_exception"
        tb = traceback.format_exc()
        if "handle_exception" in str(tb):
            pass
        else:
            raise e2

    # Hit tokernizer directly
    env.lexer.tokenize(original)
    return

def main():
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
