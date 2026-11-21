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
#
################################################################################
"""Writes seed inputs for the postfix fuzzers.

Usage: make_seeds.py <output_dir>
Creates <output_dir>/<fuzzer>/seed_NN with valid examples of each format.
"""
import os
import sys


def policy_reply():
    # Replies as a policy server writes them: name=value lines, then an
    # empty line. Several replies in a row, as on a reused connection.
    return [
        b"action=DUNNO\n\n",
        b"action=OK\n\naction=REJECT 5.7.1 Access denied\n\n",
        b"action=DEFER_IF_PERMIT Service temporarily unavailable\n\n",
        b"action=PREPEND X-Policy: checked\nfoo=bar\n\n",
        b"action=HOLD\n\naction=dunno\n\naction=FILTER smtp:[127.0.0.1]:10025\n\n",
        b"foo=bar\n\n",
    ]


SEEDS = {
    "fuzz_policy_reply": policy_reply,
}


def main():
    out = sys.argv[1]
    for name, gen in SEEDS.items():
        d = os.path.join(out, name)
        os.makedirs(d, exist_ok=True)
        for i, s in enumerate(gen()):
            with open(os.path.join(d, "seed_%02d" % i), "wb") as f:
                f.write(s)


if __name__ == "__main__":
    main()
