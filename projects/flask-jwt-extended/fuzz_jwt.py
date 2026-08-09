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
import jwt
import atheris

from flask import Flask
from flask import jsonify

from flask_jwt_extended import create_access_token
from flask_jwt_extended import decode_token
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager
from flask_jwt_extended import verify_jwt_in_request


def get_app(key):
  """Helper method to get a flask app."""
  app = Flask(__name__)
  app.config["JWT_SECRET_KEY"] = key if key != "" else "randomfuzzkey"
  app.config["JWT_TOKEN_LOCATION"] = ["query_string"]
  JWTManager(app)

  @app.route("/protected", methods=["GET"])
  @jwt_required()
  def access_protected():
    return jsonify(foo="bar")

  return app


def test_encodings(data):
  fdp = atheris.FuzzedDataProvider(data)
  app = get_app(fdp.ConsumeUnicodeNoSurrogates(64))
  with app.test_request_context():
    token = create_access_token(fdp.ConsumeUnicodeNoSurrogates(sys.maxsize))
    decoded_token = decode_token(token)


def test_get(data):
  fdp = atheris.FuzzedDataProvider(data)
  app = get_app(fdp.ConsumeUnicodeNoSurrogates(64))

  @app.route("/custom", methods=["GET"])
  def custom():
    jwt_header, jwt_data = verify_jwt_in_request(optional=fdp.ConsumeBool(),
                                                 fresh=fdp.ConsumeBool(),
                                                 refresh=fdp.ConsumeBool())
    if fdp.ConsumeBool():
      return jsonify(foo=fdp.ConsumeUnicodeNoSurrogates(256))
    else:
      return {
          fdp.ConsumeUnicodeNoSurrogates(124):
              fdp.ConsumeUnicodeNoSurrogates(124)
      }

  url = "/custom"
  test_client = app.test_client()
  with app.test_request_context():
    try:
      token = create_access_token(fdp.ConsumeUnicodeNoSurrogates(256))
    except jwt.exceptions.InvalidKeyError:
      return

  headers = {"Authorization": "Bearer {}".format(token)}
  response = test_client.get(url, headers=headers)

  # Get the json return from /custom
  response.get_json()


def TestOneInput(data):
  fdp = atheris.FuzzedDataProvider(data)
  if fdp.ConsumeBool():
    test_get(data)
  else:
    test_encodings(data)


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
