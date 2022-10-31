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
import traceback

from werkzeug.wrappers import Request
import flask
from flask_restx.reqparse import RequestParser


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    try:
        req = Request.from_values(fdp.ConsumeUnicodeNoSurrogates(1024))
    except:
        # We don't care about errors in werkzeug Request.
        return

    app = flask.Flask("fuzz")
    try:
        with app.app_context():
            parser = RequestParser()
            parser.add_argument("ex1")
            parser.add_argument("ex2")
            # Parse arbitrary req
            parser.parse_args(req)
    except Exception as e2:
        tb = traceback.format_exc()
        # We don't care about werkzeug errors
        if "werkzeug" in str(tb):
            pass
        else:
            raise e2


def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
