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
   from arrow import utcnow
   from colour import Color
   from uuid import uuid4

   import sqlalchemy
   from sqlalchemy.sql import text, select
   from sqlalchemy.exc import SQLAlchemyError
   from sqlalchemy import (
      create_engine, Integer, String, MetaData,
      Table, Column, Sequence
   )
   from sqlalchemy_utils import (
      ArrowType, ChoiceType, ColorType, CountryType,
      Country, EmailType, JSONType, IPAddressType,
      ScalarListType, URLType, UUIDType, WeekDays,
      WeekDaysType
   )

   # The following imports are needed to make the pyinstaller
   # executable work.
   from babel import Locale
   import babel.dates
   import babel.numbers


@atheris.instrument_func
def TestInput(data):
    if len(data) < 10:
        pass

    fdp = atheris.FuzzedDataProvider(data)

    metadata = MetaData()
    fuzz_table = Table('fuzz_table', metadata,
        Column('id', Integer, Sequence('id_seq'), primary_key=True),
        Column('Col1', String),
        Column('Col2', ArrowType),
        Column('Col3', ChoiceType(
            [(u'c1', u'Choice 1'),(u'c2', u'Choice 2')]
        )),
        Column('Col4', ColorType),
        Column('Col5', CountryType),
        Column('Col6', EmailType),
        Column('Col7', JSONType),
        Column('Col8', IPAddressType),
        Column('Col9', ScalarListType(int)),
        Column('Col10', URLType),
        Column('Col11', UUIDType(binary=False)),
        Column('Col12', WeekDaysType)
    )

    engine = create_engine('sqlite:///fuzz.db')
    metadata.create_all(engine)
    try:
        with engine.connect() as conn:
            conn.execute(text(fdp.ConsumeString(100))) 
            ins = fuzz_table.insert().values(
                 Col1=fdp.ConsumeString(100),
                 Col2=utcnow(),
                 Col3=u'c1' if fdp.ConsumeBool() else u'c2',
                 Col4=Color("#{:02x}{:02x}{:02x}".format(
                    fdp.ConsumeIntInRange(0,255),
                    fdp.ConsumeIntInRange(0,255),
                    fdp.ConsumeIntInRange(0,255)
                 )),
                 Col5=Country('US'),
                 Col6=fdp.ConsumeString(20),
                 Col7={
                     fdp.ConsumeString(2):fdp.ConsumeString(10),
                     fdp.ConsumeString(2):fdp.ConsumeString(10),
                     fdp.ConsumeString(2):fdp.ConsumeString(10)
                 },
                 Col8="%d.%d.%d.%d"%(
                    fdp.ConsumeIntInRange(0,255),
                    fdp.ConsumeIntInRange(0,255),
                    fdp.ConsumeIntInRange(0,255),
                    fdp.ConsumeIntInRange(0,255)
                 ),
                 Col9=[fdp.ConsumeInt(8),fdp.ConsumeInt(8),fdp.ConsumeInt(8)],
                 Col10=fdp.ConsumeUnicode(20),
                 Col11=uuid4(),
                 Col12=WeekDays("{0:07b}".format(fdp.ConsumeIntInRange(0,31)))
            )
            ins.compile()
            conn.execute(ins) 
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
