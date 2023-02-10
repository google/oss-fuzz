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

import h11


def fuzz_headers(data):
  fdp = atheris.FuzzedDataProvider(data)
  fuzz_headers = [(fdp.ConsumeBytes(32), fdp.ConsumeBytes(1024)),
                  (fdp.ConsumeBytes(32), fdp.ConsumeBytes(1024))]
  try:
    normalized_headers = h11._headers.normalize_and_validate(fuzz_headers)
    get_comma_header(normalized_headers, b'connection')
    set_comma_header(normalized_headers, fdp.ConsumeBytes(64))
  except (h11._util.ProtocolError):
    pass

  try:
    h11._headers.has_expect_100_continue(
        h11._events.Request(method='GET',
                            target='/',
                            headers=fuzz_headers,
                            http_version='1.0'))
  except (h11._util.ProtocolError):
    pass


def fuzz_receivebuffer(data):
  fdp = atheris.FuzzedDataProvider(data)
  rec_buf = h11._receivebuffer.ReceiveBuffer()
  for i in range(5):
    rec_buf += fdp.ConsumeBytes(124)
  rec_buf.maybe_extract_at_most(fdp.ConsumeIntInRange(1, 100))
  rec_buf.maybe_extract_next_line()
  rec_buf.maybe_extract_lines()


def fuzz_connection(data):
  fdp = atheris.FuzzedDataProvider(data)
  conn = h11.Connection(our_role=h11.CLIENT)
  event = h11.Request(
      method="GET",
      target="/get",
      headers=[("Host", "127.0.0.1"), ("Connection", "close")],
  )

  conn.send(event)
  conn.send(h11.EndOfMessage())
  conn.next_event()
  conn.receive_data(fdp.ConsumeBytes(1024))

  try:
    event2 = h11.Request(
        method=fdp.ConsumeUnicodeNoSurrogates(5),
        target=fdp.ConsumeUnicodeNoSurrogates(124),
        headers=[(fdp.ConsumeUnicodeNoSurrogates(5),
                  fdp.ConsumeUnicodeNoSurrogates(124)),
                 (fdp.ConsumeUnicodeNoSurrogates(124),
                  fdp.ConsumeUnicodeNoSurrogates(124))],
    )

    conn.send(event2)
    conn.send(h11.EndOfMessage())
    conn.next_event()
    conn.receive_data(fdp.ConsumeBytes(1024))
  except (h11._util.ProtocolError):
    pass


def TestOneInput(data):
  fuzz_headers(data)
  fuzz_receivebuffer(data)
  fuzz_connection(data)


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
