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

import atheris
import datetime
import logging
logging.getLogger().setLevel(logging.CRITICAL)

from opencensus.trace import span
from opencensus.trace import span_context
from opencensus.trace import time_event


def TestOneInput(input_bytes):
  fdp = atheris.FuzzedDataProvider(input_bytes)

  span_context_item = span_context.SpanContext(
      span_id=fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(1, 512)))
  annotation_time = datetime.date.fromtimestamp(fdp.ConsumeInt(4))
  annotation = time_event.Annotation(
      annotation_time,
      fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(1, 512)))

  name = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(1, 512))
  span_item = span.Span(
      name=name,
      attributes={
          fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(1, 512)):
              fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(1, 512))
      },
      start_time=str(fdp.ConsumeInt(4)),
      end_time=str(fdp.ConsumeInt(4)),
      span_id=fdp.ConsumeInt(4),
      annotations=[annotation])
  span.format_span_json(span_item)


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
