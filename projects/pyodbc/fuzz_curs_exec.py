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
"""Fuzzer that targets native code of pyodbc with a fake odbc driver"""
import os
import sys
import atheris
import pyodbc

@atheris.instrument_func
def fuzz_exec(data):
    fdp = atheris.FuzzedDataProvider(data)
    connstr = "DRIVER=FUZZ;"
    s1 = fdp.ConsumeUnicodeNoSurrogates(50)
    if "DRIVER" in s1:
        return
    cstr = connstr + s1
    connection_obj = pyodbc.connect(cstr)
    csr = connection_obj.cursor()
    try:
        csr.execute(fdp.ConsumeUnicodeNoSurrogates(20))
    except Exception as e:
        if "Invalid string or buffer length" in str(e):
            pass
        else:
            raise e
    return 0

@atheris.instrument_func
def TestOneInput(data):
    try:
        return fuzz_exec(data)
    except SystemError:
        return 0


def main():
    # Write the odbcinst.ini file
    dir_path = os.path.dirname(os.path.realpath(__file__))
    with open("/tmp/odbcinst.ini", "w") as f:
        f.write("[FUZZ]\n")
        f.write("Driver=%s/fuzzodbc.so\n"%(dir_path))
    os.environ['ODBCSYSINI'] = '/tmp/'
    
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
