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
from confluent_kafka import Consumer, KafkaException, TopicPartition


def TestInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    def dummy_callback(err, partitions):
        pass

    try:
        c = Consumer({
            'group.id': fdp.ConsumeConsumeUnicodeNoSurrogates(10),
            'socket.timeout.ms': fdp.ConsumeIntInRange(10,2000),
            'session.timeout.ms': fdp.ConsumeIntInRange(10,2000),
            'on_commit': dummy_callback})
    except Exception as e:
        # If the consumer fails, we just retry
        return

    try:
        c.subscribe(
            [fdp.ConsumeUnicodeNoSurrogates(10)],
            on_assign=dummy_callback,
            on_revoke=dummy_callback
        )
        c.unsubscribe()

        msg = c.poll(timeout=0.001)
        msglist = c.consume(
            num_messages=fdp.ConsumeIntInRange(1,10),
            timeout=0.001
        )

        partitions = list(
            map(
                lambda part: TopicPartition(fdp.ConsumeUnicodeNoSurrogates(10).replace('\x00', ''), part),
                range(0, 100, 3)
            )
        )
        c.assign(partitions)
        c.unassign()

        c.commit(asynchronous=fdp.ConsumeBool())
        c.committed(partitions, timeout=0.001)

        c.list_topics(timeout=0.2)
        c.list_topics(topic=fdp.ConsumeString(10), timeout=0.1)
    except KafkaException as e:
        pass

    c.close()


def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestInput, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
