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
with atheris.instrument_imports():
    from psycopg2 import sql

def TestInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    try:
        query = sql.SQL(fdp.ConsumeString(10)).format(sql.SQL(fdp.ConsumeString(1)).join([sql.Identifier(fdp.ConsumeString(5)), fdp.ConsumeString(5)]),sql.Identifier(fdp.ConsumeString(5)))
        comp = sql.Composed([query, sql.Identifier(fdp.ConsumeString(5))])
        query.string()
        comp.seq()
    except TypeError as e:
       if "Composed elements must be Composable" in str(e):
          #acceptable result
          pass
       else:
           raise e
def main():
    atheris.Setup(sys.argv, TestInput, enable_python_coverage=True)
    atheris.Fuzz()

if __name__ == "__main__":
  main()
