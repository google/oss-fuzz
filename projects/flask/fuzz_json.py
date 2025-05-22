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
  import flask
  from flask import Flask as _Flask
  from werkzeug.http import parse_set_header


class FuzzFlask(_Flask):
  testing = True
  secret_key = "fuzz test key"

def TestOneInput(data):
  fdp = atheris.FuzzedDataProvider(data)
  app = FuzzFlask("flask_test", root_path=os.path.dirname(__file__))
  app.config["DEBUG"] = True
  app.config["TRAP_BAD_REQUEST_ERRORS"] = False

  @app.route("/json", methods=["POST"])
  def post_json():
    flask.request.get_json()
    return None

  parse_set_header(fdp.ConsumeUnicode(fdp.ConsumeIntInRange(0, 512)))
  
  client = app.test_client()

  try:
    app.add_url_rule(
      fdp.ConsumeUnicode(fdp.ConsumeIntInRange(0, 512)),
      endpoint = "randomendpoint"
    )
  except ValueError:
    None

  try:
    client.post(
      "/json",
      data=fdp.ConsumeUnicode(fdp.ConsumeIntInRange(0, 512)),
      content_type="application/json"
    )
  except (TypeError, UnicodeEncodeError):
    None


def main():
  atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
  atheris.Fuzz()

if __name__ == "__main__":
  main()
