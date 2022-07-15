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
from psycopg2 import sql 

def TestInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    try:
        # Create an SQL statement and perform a set of operations on it.
        query = sql.SQL(fdp.ConsumeString(100))
        i1 = sql.Identifier(fdp.ConsumeString(25))
        i2 = sql.Identifier(fdp.ConsumeString(25))
        i3 = sql.Identifier(fdp.ConsumeString(25))
        i4 = sql.Identifier(fdp.ConsumeString(25))
        i5 = sql.Identifier(fdp.ConsumeString(25))
        q1 = sql.SQL(fdp.ConsumeString(100))
        q1.join([i1, i2])
        query.format(q1, i3,  i4)
        comp = sql.Composed([query, i5])
    except (TypeError, ValueError) as e:
       pass

def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestInput, enable_python_coverage=True)
    atheris.Fuzz()

if __name__ == "__main__":
  main()
