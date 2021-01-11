#!/usr/bin/python3

# Copyright 2021 Google LLC
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

import yaml

import jinja2


def TestOneInput(input_bytes):
  # split input in two : template, and dictionary of value (using yaml)
  sep = input_bytes.find(b"\x00")
  if sep <= 0:
    return
  t = input_bytes[:sep-1]
  try:
    context = yaml.load(input_bytes[sep+1:], Loader=yaml.FullLoader)
  except yaml.YAMLError:
    pass

  # run jinja renderer
  try:
    template = jinja2.Template(t)
    template.render(context)
  except jinja2.TemplateError:
    pass
  # do not care for these exceptions which are too noisy
  except TypeError:
    pass


def main():
  atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
