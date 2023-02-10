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
   import sqlalchemy
   from sqlalchemy import create_engine, Table, Column, Integer, MetaData
   from sqlalchemy.sql import text
   from sqlalchemy.exc import SQLAlchemyError
   import sqlalchemy_jsonfield
   from sqlalchemy_jsonfield import JSONField

@atheris.instrument_func
def TestInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    metadata = MetaData()
    fuzz_table = Table('fuzz_table', metadata,
        Column('id', Integer, primary_key=True),
        Column('Col1',
           JSONField(enforce_string=fdp.ConsumeBool(),enforce_unicode=fdp.ConsumeBool())
       )
    )

    engine = create_engine('sqlite:///fuzz.db')
    metadata.create_all(engine)
    try:
        with engine.connect() as conn:
            conn.execute(text(fdp.ConsumeString(100))) 
    except (SQLAlchemyError, UnicodeEncodeError) as e:
       pass
    except ValueError as e:
      if "the query contains a null character" not in str(e):
         raise e

def main():
  atheris.Setup(sys.argv, TestInput, enable_python_coverage=True)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
