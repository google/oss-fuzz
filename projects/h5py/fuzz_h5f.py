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

import h5py
from h5py import h5f, h5p


def TestOneInput(data):
  fdp = atheris.FuzzedDataProvider(data)

  image = fdp.ConsumeUnicodeNoSurrogates(sys.maxsize)

  fapl = h5p.create(h5py.h5p.FILE_ACCESS)
  fapl.set_fapl_core()
  try:
    fapl.set_file_image(image)
  except ValueError:
    return
  except TypeError:
    return

  fid = h5f.open("/tmp/tmpf.h5p", h5py.h5f.ACC_RDONLY, fapl=fapl)
  f = h5py.File(fid)
 

def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
