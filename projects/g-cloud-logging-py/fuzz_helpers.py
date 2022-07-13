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
    import google.cloud.logging_v2._helpers as helpers
    import google.cloud.logging_v2.handlers._helpers as handlers_helpers

def TestInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    helpers.retrieve_metadata_server(fdp.ConsumeString(100))
    helpers._normalize_severity(fdp.ConsumeInt(100))
    helpers._add_defaults_to_filter(fdp.ConsumeString(100))

    handlers_helpers.get_request_data_from_flask()
    handlers_helpers.get_request_data_from_django()
    handlers_helpers._parse_trace_parent(fdp.ConsumeString(100))
    handlers_helpers._parse_xcloud_trace(fdp.ConsumeString(100))
    handlers_helpers.get_request_data()

def main():
    atheris.Setup(sys.argv, TestInput, enable_python_coverage=True)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
