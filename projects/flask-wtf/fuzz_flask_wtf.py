#!/usr/bin/python3
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
import sys
import atheris

from flask import Flask
from flask_wtf.csrf import validate_csrf, generate_csrf
from flask_wtf.i18n import translations
from wtforms import ValidationError


def get_app(fdp):
  """Helper method to get a flask app."""
  app = Flask(__name__)
  key1 = fdp.ConsumeUnicodeNoSurrogates(124)
  key2 = fdp.ConsumeUnicodeNoSurrogates(124)
  app.secret_key = key1 if key1 != "" else "random key"
  app.config["WTF_CSRF_SECRET_KEY"] = key2 if key2 != "" else "random key 2"
  return app


def fuzz_i18n(data):
  fdp = atheris.FuzzedDataProvider(data)
  translations.gettext(fdp.ConsumeUnicodeNoSurrogates(124))
  translations.ngettext(fdp.ConsumeUnicodeNoSurrogates(124),
                        fdp.ConsumeUnicodeNoSurrogates(124), 2)


def fuzz_csrf(data):
  fdp = atheris.FuzzedDataProvider(data)
  app = get_app(fdp)
  with app.test_request_context():
    try:
      validate_csrf(
          generate_csrf(secret_key=fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 1024)),
                        token_key=fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 1024))))
    except ValidationError:
      pass


def TestOneInput(data):
  fuzz_i18n(data)
  fuzz_csrf(data)


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
