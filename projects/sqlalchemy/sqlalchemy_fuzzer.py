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

import sys
import atheris

with atheris.instrument_imports():
  import sqlalchemy
  from sqlalchemy import create_engine
  from sqlalchemy import Table, Column, Integer, String, MetaData
  from sqlalchemy.sql import text

@atheris.instrument_func
def TestOneInput(input_bytes):
    try:
        sql_string = input_bytes.decode("utf-8")
        metadata = MetaData()
        fuzz_table = Table('fuzz_table', metadata,
          Column('id', Integer, primary_key=True),
          Column('column1', String),
          Column('column2', String),
        )

        engine = create_engine('sqlite:///fuzz.db')
        metadata.create_all(engine)
        statement = text(sql_string)
        with engine.connect() as conn:            
            conn.execute(statement)
    except Exception as e:
        pass


def main():
  atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
