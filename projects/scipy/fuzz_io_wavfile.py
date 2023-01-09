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

from scipy.io import wavfile


def TestOneInput(data):
  # Give enough bytes to pass initial checks
  if len(data) < 20:
    return
  wav_filepath = "/tmp/temp.wav"
  with open(wav_filepath, "wb") as f:
    f.write(data)
  try:
    wavfile.read(wav_filepath)
  except ValueError:
    # Not interesting.
    pass


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
