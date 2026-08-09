#!/usr/bin/env python3
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
#
################################################################################

from pathlib import Path, PosixPath
import re
import sys
import os
import fnmatch
from typing import List, Set
import shutil

excluded_CVEs_or_CRBugs = ["CR410030", "CR445267", "CR1150371"]

keywords_to_exclude = {
    "WebAssembly",
    "Worker",
}

# v8 runtime functions regex - https://chromium.googlesource.com/v8/v8/+/refs/heads/main/src/runtime/runtime.h
v8_runtime_function_pattern = r"%\w+\("


def get_js_files(path: str) -> Set[PosixPath]:
    path = Path(path)
    js_files = {x for x in path.glob("**/*.js") if path.is_dir()}
    if not js_files:
        print(f"No JS files found in {path}")
    return js_files


if __name__ == "__main__":
    # Exclude tests marked by Hermes test suite to skip from corpus
    test262_tests = get_js_files("./test262/test")
    esprima_tests = get_js_files("./hermes/external/esprima/test_fixtures")
    flow_tests = get_js_files("./hermes/external/flowtest/test/flow")
    mjsunit_tests = get_js_files("./v8/test/mjsunit")

    hermes_skiplist_path = Path("./hermes/utils/testsuite/testsuite_skiplist.py")
    if not hermes_skiplist_path.is_file():
        for file in os.listdir("./hermes"):
            if fnmatch.fnmatch(file, "testsuite_skiplist.py"):
                hermes_skiplist_path = Path(file)
                break

    shutil.copy(hermes_skiplist_path, "./testsuite_skiplist.py")
    from testsuite_skiplist import (
        SKIP_LIST,
        PERMANENT_SKIP_LIST,
        UNSUPPORTED_FEATURES,
        PERMANENT_UNSUPPORTED_FEATURES,
    )

    # Exclude tests in mjsunit using v8 runtime functions
    for test in mjsunit_tests.copy():
        test_code = test.open().read()
        if re.search(v8_runtime_function_pattern, test_code):
            print(f"Removed: {test}")
            test.unlink()
            mjsunit_tests.discard(test)

    # Exclude tests marked explicitly to skip in Hermes test suite
    tests_to_remove = (
        {test_name for test_name in test262_tests if str(test_name) in SKIP_LIST}
        | {test_name for test_name in esprima_tests if str(test_name) in SKIP_LIST}
        | {test_name for test_name in flow_tests if str(test_name) in SKIP_LIST}
        | {
            test_name
            for test_name in mjsunit_tests
            if str(test_name).lstrip("v8/test/") in SKIP_LIST
        }
        | {
            test_name
            for test_name in test262_tests
            if str(test_name) in PERMANENT_SKIP_LIST
        }
        | {
            test_name
            for test_name in esprima_tests
            if str(test_name) in PERMANENT_SKIP_LIST
        }
        | {
            test_name
            for test_name in flow_tests
            if str(test_name) in PERMANENT_SKIP_LIST
        }
        | {
            test_name
            for test_name in mjsunit_tests
            if str(test_name).lstrip("v8/test/") in PERMANENT_SKIP_LIST
        }
    )
    for test in tests_to_remove:
        print(f"Removed: {test}")
        test.unlink()
        test262_tests.discard(test)
        esprima_tests.discard(test)
        mjsunit_tests.discard(test)
        flow_tests.discard(test)

    # Exclude tests by keywords found in file contents
    keywords_to_exclude.update(UNSUPPORTED_FEATURES, PERMANENT_UNSUPPORTED_FEATURES)
    all_tests = test262_tests | esprima_tests | flow_tests | mjsunit_tests
    for test in all_tests:
        test_code = test.open().read()
        for keyword in keywords_to_exclude:
            if keyword in test_code or keyword in str(test):
                print(f"Removed: {test}")
                test.unlink()
                break

    # Filter v8 bugs before including in corpus
    v8_pocs = get_js_files("./v8-vulnerabilities/pocs")
    for poc in v8_pocs:
        try:
            # Exclude specific CVEs or CR bugs
            if any(f"{id}.js" in str(poc) for id in excluded_CVEs_or_CRBugs):
                print(f"Removed: {poc}")
                poc.unlink()
                continue

            poc_code = poc.open().read()

            # Exclude JIT bugs and other bugs using v8 runtime functions
            if re.search(v8_runtime_function_pattern, poc_code):
                print(f"Removed: {poc}")
                poc.unlink()
                continue

            # Exclude bugs with features Hermes does not support
            for keyword in keywords_to_exclude:
                if keyword in poc_code:
                    print(f"Removed: {poc}")
                    poc.unlink()
                    break

        except UnicodeDecodeError:
            # The PoC was likely generated by a fuzzer mutating at the byte level which we can exclude from the corpus
            pass
