#!/usr/bin/env python3
# Copyright 2026 Google LLC
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
################################################################################

"""Generate seed corpora for yyjson patch fuzz targets."""

import argparse
import os
import struct
import zipfile
from pathlib import Path


# These seed pairs are derived from yyjson's patch unit tests:
#   yyjson/test/test_json_patch.c
#   yyjson/test/test_json_merge_patch.c
#
# Each generated seed uses the fuzz target input format:
#   uint16 little-endian base document length,
#   followed by the base JSON document and patch JSON document.

PATCH_SEEDS = (
    # A.1. Adding an Object Member
    ("{\"foo\":\"bar\"}",
     "[{\"op\":\"add\",\"path\":\"/baz\",\"value\":\"qux\"}]"),

    # A.2. Adding an Array Element
    ("{\"foo\":[\"bar\",\"baz\"]}",
     "[{\"op\":\"add\",\"path\":\"/foo/1\",\"value\":\"qux\"}]"),

    # A.3. Removing an Object Member
    ("{\"foo\":\"bar\",\"baz\":\"qux\"}",
     "[{\"op\":\"remove\",\"path\":\"/baz\"}]"),

    # A.4. Removing an Array Element
    ("{\"foo\":[\"bar\",\"qux\",\"baz\"]}",
     "[{\"op\":\"remove\",\"path\":\"/foo/1\"}]"),

    # A.5. Replacing a Value
    ("{\"foo\":\"bar\",\"baz\":\"qux\"}",
     "[{\"op\":\"replace\",\"path\":\"/baz\",\"value\":\"boo\"}]"),

    # A.6. Moving a Value
    ("{\"foo\":{\"bar\":\"baz\",\"waldo\":\"fred\"},\"qux\":{\"corge\":\"grault\"}}",
     "[{\"op\":\"move\",\"from\":\"/foo/waldo\",\"path\":\"/qux/thud\"}]"),

    # A.7. Moving an Array Element
    ("{\"foo\":[\"all\",\"grass\",\"cows\",\"eat\"]}",
     "[{\"op\":\"move\",\"from\":\"/foo/1\",\"path\":\"/foo/3\"}]"),

    # A.8. Testing a Value: Success
    ("{\"baz\":\"qux\",\"foo\":[\"a\",2,\"c\"]}",
     "[{\"op\":\"test\",\"path\":\"/baz\",\"value\":\"qux\"},"
     "{\"op\":\"test\",\"path\":\"/foo/1\",\"value\":2}]"),

    # A.9. Testing a Value: Error
    ("{\"baz\":\"qux\"}",
     "[{\"op\":\"test\",\"path\":\"/baz\",\"value\":\"bar\"}]"),

    # A.10. Adding a Nested Member Object
    ("{\"foo\":\"bar\"}",
     "[{\"op\":\"add\",\"path\":\"/child\",\"value\":{\"grandchild\":{}}}]"),

    # A.11. Ignoring Unrecognized Elements
    ("{\"foo\":\"bar\"}",
     "[{\"op\":\"add\",\"path\":\"/baz\",\"value\":\"qux\",\"xyz\":123}]"),

    # A.12. Adding to a Nonexistent Target
    ("{\"foo\":\"bar\"}",
     "[{\"op\":\"add\",\"path\":\"/baz/bat\",\"value\":\"qux\"}]"),

    # A.13. Invalid JSON Patch Document
    ("{\"foo\":\"bar\"}",
     "[{\"op\":\"add\",\"path\":\"/baz\",\"value\":\"qux\",\"op\":\"remove\"}]"),

    # A.14. ~ Escape Ordering
    ("{\"/\":9,\"~1\":10}",
     "[{\"op\":\"test\",\"path\":\"/~01\",\"value\":10}]"),

    # A.15. Comparing Strings and Numbers
    ("{\"/\":9,\"~1\":10}",
     "[{\"op\":\"test\",\"path\":\"/~01\",\"value\":\"10\"}]"),

    # A.16. Adding an Array Value
    ("{\"foo\":[\"bar\"]}",
     "[{\"op\":\"add\",\"path\":\"/foo/-\",\"value\":[\"abc\",\"def\"]}]"),

    # invalid parameter
    ("", "[]"),
    ("[]", ""),
    ("", ""),
    ("[]", "{}"),

    # error with index
    ("[]",
     "[{\"op\":\"add\",\"path\":\"/-\",\"value\":0},"
     "{\"op\":\"add\",\"path\":\"/-\",\"value\":1},"
     "123]"),
    ("[]",
     "[{\"op\":\"add\",\"path\":\"/-\",\"value\":0},"
     "{\"op\":\"add\",\"path\":\"/-\",\"value\":1},"
     "{\"op\":\"err\",\"path\":\"/-\",\"value\":1}]"),
    ("[]",
     "[{\"op\":\"add\",\"path\":\"/-\",\"value\":0},"
     "{\"op\":\"add\",\"path\":\"/-\",\"value\":1},"
     "{\"path\":\"/-\",\"value\":1}]"),
    ("[]",
     "[{\"op\":\"add\",\"path\":\"/-\",\"value\":0},"
     "{\"op\":\"add\",\"path\":\"/-\",\"value\":1},"
     "{\"op\":\"add\",\"value\":2}]"),
    ("[]",
     "[{\"op\":\"add\",\"path\":\"/-\",\"value\":0},"
     "{\"op\":\"add\",\"path\":\"/-\",\"value\":1},"
     "{\"op\":\"add\",\"path\":null,\"value\":2}]"),

    # error op
    ("[1]", "[{\"op\":0,\"path\":\"/0\",\"value\":0}]"),
    ("[1]", "[{\"op\":\"\",\"path\":\"/0\",\"value\":0}]"),
    ("[1]", "[{\"op\":\"at\",\"path\":\"/0\",\"value\":0}]"),
    ("[1]", "[{\"op\":\"set\",\"path\":\"/0\",\"value\":0}]"),
    ("[1]", "[{\"op\":\"puts\",\"path\":\"/0\",\"value\":0}]"),
    ("[1]", "[{\"op\":\"delete\",\"path\":\"/0\",\"value\":0}]"),
    ("[1]", "[{\"op\":\"unknown\",\"path\":\"/0\",\"value\":0}]"),

    # add
    ("[1]", "[{\"op\":\"add\",\"value\":0}]"),
    ("[0]", "[{\"op\":\"add\",\"path\":\"/1\"}]"),
    ("[0]", "[{\"op\":\"add\",\"path\":\"/1\",\"value\":1}]"),
    ("[0]", "[{\"op\":\"add\",\"path\":\"/2\",\"value\":1}]"),
    ("[0]", "[{\"op\":\"add\",\"path\":\"/~2\",\"value\":1}]"),
    ("[0]", "[{\"op\":\"add\",\"path\":\"\",\"value\":1}]"),

    # remove
    ("[1]", "[{\"op\":\"remove\"}]"),
    ("[1]", "[{\"op\":\"remove\",\"path\":0}]"),
    ("[1]", "[{\"op\":\"remove\",\"path\":\"\"}]"),
    ("[1]", "[{\"op\":\"remove\",\"path\":\"/-\"}]"),
    ("[1]", "[{\"op\":\"remove\",\"path\":\"/0\"}]"),

    # replace
    ("[1]", "[{\"op\":\"replace\",\"value\":0}]"),
    ("[0]", "[{\"op\":\"replace\",\"path\":\"/1\"}]"),
    ("[0]", "[{\"op\":\"replace\",\"path\":\"/0\",\"value\":1}]"),
    ("[0]", "[{\"op\":\"replace\",\"path\":\"/1\",\"value\":1}]"),
    ("[0]", "[{\"op\":\"replace\",\"path\":\"/~2\",\"value\":1}]"),
    ("[0]", "[{\"op\":\"replace\",\"path\":\"\",\"value\":1}]"),

    # move
    ("[[1,2],[3,4]]", "[{\"op\":\"move\",\"from\":\"/0/0\"}]"),
    ("[[1,2],[3,4]]", "[{\"op\":\"move\",\"path\":\"/1/0\"}]"),
    ("[[1,2],[3,4]]", "[{\"op\":\"move\",\"from\":\"/0/0\",\"path\":\"/1/0\"}]"),
    ("[[1,2],[3,4]]", "[{\"op\":\"move\",\"from\":0,\"path\":\"/1/0\"}]"),
    ("[[1,2],[3,4]]", "[{\"op\":\"move\",\"from\":\"/0/a\",\"path\":\"/1/0\"}]"),
    ("[[1,2],[3,4]]", "[{\"op\":\"move\",\"from\":\"/0/0\",\"path\":\"/1/a\"}]"),
    ("[[1,2],[3,4]]", "[{\"op\":\"move\",\"from\":\"/0/~\",\"path\":\"/1/0\"}]"),
    ("[[1,2],[3,4]]", "[{\"op\":\"move\",\"from\":\"\",\"path\":\"\"}]"),
    ("[[1,2],[3,4]]", "[{\"op\":\"move\",\"from\":\"/0/0\",\"path\":\"\"}]"),

    # copy
    ("[[1,2],[3,4]]", "[{\"op\":\"copy\",\"from\":\"/0/0\"}]"),
    ("[[1,2],[3,4]]", "[{\"op\":\"copy\",\"path\":\"/1/0\"}]"),
    ("[[1,2],[3,4]]", "[{\"op\":\"copy\",\"from\":\"/0/0\",\"path\":\"/1/0\"}]"),
    ("[[1,2],[3,4]]", "[{\"op\":\"copy\",\"from\":0,\"path\":\"/1/0\"}]"),
    ("[[1,2],[3,4]]", "[{\"op\":\"copy\",\"from\":\"/0/a\",\"path\":\"/1/0\"}]"),
    ("[[1,2],[3,4]]", "[{\"op\":\"copy\",\"from\":\"/0/0\",\"path\":\"/1/a\"}]"),
    ("[[1,2],[3,4]]", "[{\"op\":\"copy\",\"from\":\"/0/~\",\"path\":\"/1/0\"}]"),
    ("[[1,2],[3,4]]", "[{\"op\":\"copy\",\"from\":\"\",\"path\":\"\"}]"),
    ("[[1,2],[3,4]]", "[{\"op\":\"copy\",\"from\":\"/0/0\",\"path\":\"\"}]"),

    # test
    ("[1]", "[{\"op\":\"test\",\"value\":1}]"),
    ("[1]", "[{\"op\":\"test\",\"path\":\"/0\"}]"),
    ("[1]", "[{\"op\":\"test\",\"path\":\"/0\",\"value\":1}]"),
    ("[1]", "[{\"op\":\"test\",\"path\":\"/1\",\"value\":1}]"),
    ("[1]", "[{\"op\":\"test\",\"path\":\"/~2\",\"value\":1}]"),
    ("[1]", "[{\"op\":\"test\",\"path\":\"\",\"value\":2}]"),

    # multiple ops
    ("[1,2,3]",
     "[{\"op\":\"add\",\"path\":\"/3\",\"value\":4},"
     "{\"op\":\"remove\",\"path\":\"/1\"},"
     "{\"op\":\"replace\",\"path\":\"/0\",\"value\":{\"a\":0}},"
     "{\"op\":\"move\",\"from\":\"/0/a\",\"path\":\"/1\"},"
     "{\"op\":\"copy\",\"from\":\"/3\",\"path\":\"/0/b\"},"
     "{\"op\":\"test\",\"path\":\"/0\",\"value\":{\"b\":4}}]"),
)

MERGE_PATCH_SEEDS = (
    ("{\"a\":\"b\"}", "{\"a\":\"c\"}"),
    ("{\"a\":\"b\"}", "{\"b\":\"c\"}"),
    ("{\"a\":\"b\"}", "{\"a\":null }"),
    ("{\"a\":\"b\"}", "{\"a\":null }"),
    ("{\"a\":\"b\", \"b\":\"c\"}", "{\"a\":null }"),
    ("{\"a\":[\"b\"] }", "{\"a\":\"c\"}"),
    ("{\"a\":\"c\"}", "{\"a\":[\"b\"]}"),
    ("{\"a\":{\"b\":\"c\"}}", "{\"a\":{\"b\":\"d\",\"c\":null}}"),
    ("{\"a\":{\"b\":\"c\"}}", "{\"a\":[1]}"),
    ("[\"a\",\"b\"]", "[\"c\",\"d\"]"),
    ("{\"a\":\"b\"}", "[\"c\"]"),
    ("{\"a\":\"foo\"}", "null"),
    ("{\"a\":\"foo\"}", "\"bar\""),
    ("{\"e\":null}", "{\"a\":1}"),
    ("[1,2]", "{\"a\":\"b\",\"c\":null}"),
    ("{}", "{\"a\":{\"bb\":{\"ccc\":null}}}"),
)


def make_seed(base_json, patch_json):
    base = base_json.encode("utf-8")
    patch = patch_json.encode("utf-8")

    if len(base) > 0xFFFF:
        raise ValueError("base JSON is too large for uint16 split length")

    return struct.pack("<H", len(base)) + base + patch


def write_seed_corpus(out_dir, zip_name, prefix, seeds):
    out_path = out_dir / zip_name

    with zipfile.ZipFile(out_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for idx, (base_json, patch_json) in enumerate(seeds):
            zf.writestr(f"{prefix}_{idx:04d}", make_seed(base_json, patch_json))


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=os.environ.get("OUT"),
        required=os.environ.get("OUT") is None,
        help="Directory where seed corpus archives will be written.",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    write_seed_corpus(
        out_dir,
        "yyjson_patch_fuzzer_seed_corpus.zip",
        "patch",
        PATCH_SEEDS,
    )
    write_seed_corpus(
        out_dir,
        "yyjson_merge_patch_fuzzer_seed_corpus.zip",
        "merge_patch",
        MERGE_PATCH_SEEDS,
    )


if __name__ == "__main__":
    main()
