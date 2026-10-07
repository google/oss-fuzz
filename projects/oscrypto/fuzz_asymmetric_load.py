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
import sys
import atheris

from oscrypto import asymmetric, errors, backend


def TestOneInput(data):
  randfile = "/tmp/random.cert"
  with open(randfile, "wb") as f:
    f.write(data)

  if not os.path.isfile(randfile):
    return

  try:
    asymmetric.load_certificate(randfile)
  except ValueError:
    pass
  except OSError:
    pass

  try:
    asymmetric.load_private_key(randfile)
  except ValueError:
    pass
  except OSError:
    pass
  
  try:
    asymmetric.load_public_key(randfile)
  except ValueError:
    pass
  except OSError:
    pass

def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
