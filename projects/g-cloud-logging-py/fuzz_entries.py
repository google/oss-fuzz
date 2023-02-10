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

import google.cloud.logging_v2.entries as entries
from google.cloud.logging_v2.client import Client
from google.cloud.logging_v2.resource import Resource

def create_dummy_log_entry(fdp):
    return entries.LogEntry(
        log_name=fdp.ConsumeString(20),
        labels={
            fdp.ConsumeString(10):fdp.ConsumeString(20),
            fdp.ConsumeString(10):fdp.ConsumeString(20)
        },
        insert_id=fdp.ConsumeString(20),
        timestamp=fdp.ConsumeString(20),
        resource=Resource(type="global", labels={}),
        trace=fdp.ConsumeString(20),
        span_id=fdp.ConsumeString(20),
        trace_sampled=fdp.ConsumeBool(),
        source_location=LogEntrySourceLocation(
            file=fdp.ConsumeString(20),
            line=fdp.ConsumeString(20),
            function=fdp.ConsumeString(20)
        ),
        operation=LogEntryOperation(
            id=fdp.ConsumeString(20),
            producer=fdp.ConsumeString(20),
            first=fdp.ConsumeBool(),
            last=fdp.ConsumeBool()
        )
    )

def TestInput(data):
    if len(data) < 1:
       return

    fdp = atheris.FuzzedDataProvider(data)

    try:
        entries._int_or_none(fdp.ConsumeInt(100))
        entries.logger_name_from_path(fdp.ConsumeString(100))
        entries.logger_name_from_path(fdp.ConsumeString(100),fdp.ConsumeString(50))

        log_entry = create_dummy_log_entry(fdp)
        log_entry.to_api_repr()

        TextEntry(log_entry).to_api_repr()
        StructEntry(log_entry).to_api_repr()
        
        protobuf_entry = ProtobufEntry(log_entry)
        protobuf_entry.payload_pb()
        protobuf_entry.payload_json()
        protobuf_entry.to_api_repr()
    except ValueError as e:
        if "did not match expected pattern" not in str(e):
            raise e

def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestInput, enable_python_coverage=True)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
