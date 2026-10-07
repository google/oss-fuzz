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
    from confluent_kafka import Producer, KafkaException

def TestInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    p = Producer({
        'socket.timeout.ms': fdp.ConsumeIntInRange(10,2000),
        'message.timeout.ms': fdp.ConsumeIntInRange(10,2000)
    })

    p.produce(fdp.ConsumeUnicodeNoSurrogates(20).replace('\x00', ''))
    p.produce(
        fdp.ConsumeUnicodeNoSurrogates(20).replace('\x00', ''),
        value=fdp.ConsumeString(20),
        key=fdp.ConsumeString(20)
    )

    def on_delivery(err, msg):
        pass

    p.produce(
        topic=fdp.ConsumeUnicodeNoSurrogates(20),
        value=fdp.ConsumeUnicodeNoSurrogates(20),
        partition=fdp.ConsumeIntInRange(1,10),
        callback=on_delivery
    )

    p.poll(0.001)
    p.flush(0.002)
    p.flush()

    try:
        p.list_topics(timeout=0.2)
    except KafkaException as e:
        pass

def main():
    atheris.Setup(sys.argv, TestInput, enable_python_coverage=True)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
