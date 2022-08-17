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
import queue
import atheris
import datetime

# We instrument all at the bottom
from google.cloud.pubsub_v1.subscriber import message
from google.protobuf import timestamp_pb2
from google.pubsub_v1 import types as gapic_types

RECEIVED = datetime.datetime(2012, 4, 21, 15, 0, tzinfo=datetime.timezone.utc)
PUBLISHED_MICROS = 123456
PUBLISHED = RECEIVED + datetime.timedelta(days=1, microseconds=PUBLISHED_MICROS)
PUBLISHED_SECONDS = 1234543

is_once = True

def fuzz_exactly_once_delivery_enabled_func():
    if is_once:
        return True
    return False

def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    is_once = fdp.ConsumeBool()
    gapic_pubsub_message = gapic_types.PubsubMessage(
      data=data,
      message_id="message_id",
      publish_time=timestamp_pb2.Timestamp(
        seconds=PUBLISHED_SECONDS, nanos=PUBLISHED_MICROS * 1000
      ),
      ordering_key=fdp.ConsumeUnicodeNoSurrogates(20),
    )

    msg = message.Message(
      message=gapic_pubsub_message._pb,
      ack_id = fdp.ConsumeUnicodeNoSurrogates(20),
      delivery_attempt = fdp.ConsumeIntInRange(1, 1000),
      request_queue=queue.Queue(),
      exactly_once_delivery_enabled_func = fuzz_exactly_once_delivery_enabled_func
    )
    msg.modify_ack_deadline_with_response(fdp.ConsumeIntInRange(1, 1000))
    msg.ack_with_response()
    msg.nack_with_response()

    s1 = repr(msg)

    return msg.ack_id


def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
