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

import argparse
import requests
import threading
import time
import atheris

with atheris.instrument_imports():
  from flask import Flask
  from flask_cors import CORS
  from flask import request

app = Flask(__name__)
CORS(app)
output = ""
runs_left = None

@app.errorhandler(500)
def internal_error(error):
  print(
    "Catching exception error from flask. The exception is likely "
    "printed already right above this message in the log."
  )
  return str(error), 500

@app.route("/")
def fuzz_echo():
  global output
  return output

def shutdown_server():
  func = request.environ.get('werkzeug.server.shutdown')
  if func is None:
    raise RuntimeError('Not running with the Werkzeug Server')
  func()

# We use this to force a shutdown of the app. This is to
# have a clean exit when a crash is found.
@app.route('/shutdown')
def shutdown():
  shutdown_server()
  return "Server shutdown"

class ServerThread(threading.Thread):
  def __init__(self):
    threading.Thread.__init__(self)

  def run(self):
    global app
    app.run()

def TestOneInput(data):
  global output, runs_left
  output = data

  # We use runs_left to ensure proper exit in coverage.
  if runs_left != None:
      runs_left -= 1
      # 5 may be too much here, as we will cut off some inputs. However,
      # this is to guarantee exit for now.
      if runs_left < 5:
        try:
          requests.get('http://127.0.0.1:5000/shutdown', timeout=1.02)
        except Exception:
          None
        return


  try:
    r = requests.get('http://127.0.0.1:5000', timeout=0.5)
    if r.status_code == 500:
        raise Exception(r.text)
  except requests.exceptions.ConnectionError:
    None
  except Exception as e:
    # Every other exception is raised, but we need to shutdown
    # the server before raising it.
    requests.get('http://127.0.0.1:5000/shutdown', timeout=1.02)
    raise e


def get_run_count_if_there():
  parser = argparse.ArgumentParser()
  parser.add_argument("-atheris_runs", required=False, default=None)
  args, _ = parser.parse_known_args()
  if args.atheris_runs is None:
    print("None args")
    return None
  print(f"Got a fixed set of runs {args.atheris_runs}")
  return args.atheris_runs


def main():
  global runs_left
  max_runs = get_run_count_if_there()
  if max_runs is not None:
    runs_left = int(max_runs)

  t1 = ServerThread()
  t1.start()
  atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
  atheris.Fuzz()

if __name__ == "__main__":
  main()
