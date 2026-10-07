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
   from sqlalchemy import Column, Integer, String, select, create_engine
   from sqlalchemy.orm import declarative_base, Session
   from sqlalchemy_utils import cast_if, escape_like
   from sqlalchemy.exc import SQLAlchemyError

Base = declarative_base()

class FuzzTable(Base):
    __tablename__ = "fuzz_table"

    id = Column(Integer, primary_key=True)
    name = Column(String)

@atheris.instrument_func
def TestInput(data):
    if len(data) < 10:
        pass

    fdp = atheris.FuzzedDataProvider(data)

    cast_if(FuzzTable.id, Integer)
    cast_if(FuzzTable.name, Integer)
    cast_if(FuzzTable.id, String)
    cast_if(FuzzTable.name, String)

    cast_if(fdp.ConsumeInt(10), Integer)
    cast_if(fdp.ConsumeString(10), Integer)
    cast_if(fdp.ConsumeInt(10), String)
    cast_if(fdp.ConsumeString(10), String)

    db_str = 'sqlite:///fuzz.db'

    engine = create_engine(db_str)
    Base.metadata.create_all(engine)

    try:
       with Session(engine) as session:
           name_str = fdp.ConsumeString(20)
           session.query(FuzzTable).filter(FuzzTable.name.ilike(escape_like(name_str))).all()
    except SQLAlchemyError as e:
       pass

def main():
  atheris.Setup(sys.argv, TestInput, enable_python_coverage=True)
  atheris.Fuzz()

if __name__ == "__main__":
  main()
