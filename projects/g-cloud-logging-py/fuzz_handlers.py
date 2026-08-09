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
import logging
with atheris.instrument_imports():
    import google.cloud.logging_v2.handlers.handlers as handlers
    import google.cloud.logging_v2.handlers.structured_log as log    

def TestInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    logname = fdp.ConsumeString(100)
    message = fdp.ConsumeString(100)
    record = logging.LogRecord(
        logname, logging.INFO, None, None, message, None, None
    )

    handlers.CloudLoggingFilter._infer_source_location(record)
    filter = handlers.CloudLoggingFilter(record)

    handler = log.StructuredLogHandler(
        labels={
            fdp.ConsumeString(10):fdp.ConsumeString(20),
            fdp.ConsumeString(10):fdp.ConsumeString(20)
        },
        project_id=fdp.ConsumeString(100)
    )
    try:
        handler.format(record)
        handlers._format_and_parse_message(record, handler)
        handlers.setup_logging(handler)
    except ValueError as e:
        if "Formatting field not found in record" not in str(e):
            raise e
def main():
    atheris.Setup(sys.argv, TestInput, enable_python_coverage=True)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
