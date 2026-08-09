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
    from jinja2.environment import Environment
    from jinja2.loaders import DictLoader

def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    template_str = fdp.ConsumeString(sys.maxsize)

    tmp_path = "/tmp/mytemplates"
    temp_file = os.path.join(tmp_path, "template.jinja2")
    if not os.path.isdir(tmp_path):
        os.mkdir(tmp_path)
    if os.path.isfile(temp_file):
        os.remove(temp_file)
    with open(temp_file, "wb") as fd:
        fd.write(data)

    env = Environment(loader=DictLoader({"foo": template_str}))
    try:
        env.compile_templates(tmp_path, zip=None)
    except RecursionError:
        return
    return

def main():
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
