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
import joblib
import traceback

def TestOneInput(data):
  fdp = atheris.FuzzedDataProvider(data)
  fuzz_filename = '/tmp/file_to_load'
  with open(fuzz_filename, 'wb') as fuzz_file:
    fuzz_file.write(data)

  try:
    loaded_obj = joblib.load(fuzz_filename)
  except Exception as e:
    tb = ''.join(traceback.TracebackException.from_exception(e).format())
    if "pickle.py" in tb:
      # Ignore exceptions thrown from the pickle level.
      return
    raise e

  # Anything loadable should be dumpable
  joblib.dump(loaded_obj, '/tmp/file_to_dump')

def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
