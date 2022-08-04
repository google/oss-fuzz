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

import atheris

from hypothesis import given, assume
from hypothesis import strategies as st

with atheris.instrument_imports():
  from dateutil import tz
  from dateutil.parser import isoparse


# Strategies
TIME_ZONE_STRATEGY = st.sampled_from([None, tz.UTC] +
    [tz.gettz(zname) for zname in ('America/New_York', 'America/Los_Angeles',
                                   'Australia/Sydney', 'Europe/London')])
ASCII_STRATEGY = st.characters(max_codepoint=127)


@given(dt=st.datetimes(timezones=TIME_ZONE_STRATEGY), sep=ASCII_STRATEGY)
def test_timespec_auto(dt, sep):
    if dt.tzinfo is not None:
        # Assume offset has no sub-second components
        assume(dt.utcoffset().total_seconds() % 60 == 0)

    sep = str(sep)          # Python 2.7 requires bytes
    dtstr = dt.isoformat(sep=sep)
    dt_rt = isoparse(dtstr)

    assert dt_rt == dt

if __name__ == "__main__":
     # Replay, deduplicate, and minimize any failures from previous runs:
     test_timespec_auto()

     # If that passed, we use Atheris to provide the inputs to our test:
     atheris.Setup(sys.argv, atheris.instrument_func(test_timespec_auto.hypothesis.fuzz_one_input))
     atheris.Fuzz()

