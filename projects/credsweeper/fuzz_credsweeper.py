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
# distributed under the License is distributed on an "AS IS" BASIS, # WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import sys

import atheris

with atheris.instrument_imports(enable_loader_override=False):
    import credsweeper

config_json = {
    "exclude": {"pattern": [], "extension": [".7z", ".zip"],
                "path": ["/.git/", "/.idea/", "/.svn/", "/__pycache__/", "/node_modules/", "/target/", "/venv/"]
                }, "source_ext": [".c", ".h"], "source_quote_ext": [".c", ".h", ".hpp"], "check_for_literals": True,
    "line_data_output": ["line", "line_num", "path", "value", "variable", "entropy_validation"],
    "candidate_output": ["rule", "severity", "line_data_list", "api_validation", "ml_validation", "ml_probability"],
    "validation": {}
}


# @mock.patch("json.load", MagicMock(config_json))

def fuzz_credsweeper_scan(data):
    fdp = atheris.FuzzedDataProvider(data)
    to_scan = fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 1000))

    cred_sweeper = credsweeper.app.CredSweeper()
    provider = credsweeper.file_handler.byte_content_provider.ByteContentProvider(to_scan)
    cred_sweeper.file_scan(provider)


def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, fuzz_credsweeper_scan, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
