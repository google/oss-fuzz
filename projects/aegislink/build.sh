#!/bin/bash -eu
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
# OSS-Fuzz build script for AegisLink parser fuzz targets.
# Mirror of projects/aegislink/build.sh in google/oss-fuzz.
#
# Builds one libFuzzer/Jazzer.js target per untrusted-input parser, each seeded
# from the in-tree corpus declared in mobile/src/fuzz/targets.ts.

cd "$SRC/aegislink/mobile"

# Exact lockfile versions, but skip Expo/React-Native native postinstall hooks —
# the fuzz targets are pure-logic and never touch the native tree.
npm ci --ignore-scripts

# Tooling (not saved to the lockfile): esbuild bundles the TypeScript targets +
# their pure closure to standalone CommonJS; @jazzer.js/core is the engine that
# compile_javascript_fuzzer drives.
npm install --no-save --ignore-scripts esbuild @jazzer.js/core

# Bundle once. esbuild erases the type-only imports and inlines
# tweetnacl/@noble/tweetnacl-util, so the artifact has NO RN/Expo runtime dep.
npm run fuzz:bundle

# Keep this list in sync with FUZZ_TARGETS in mobile/src/fuzz/targets.ts.
TARGETS=(
  parseIdentityQR
  parseGroupInviteLink
  universalToScheme
  parseMultiPayload
  parseGroupPostMarker
  parseLocationMessage
  unpadInnerPayload
)

for t in "${TARGETS[@]}"; do
  compile_javascript_fuzzer aegislink/mobile "fuzz/$t.fuzz.js" --sync

  # Seed corpus: dump the target's in-tree seeds (read straight from the bundle)
  # and zip them so libFuzzer starts from known-interesting inputs. The fuzzer
  # binary is named "<t>.fuzz", so the matching archive is "<t>.fuzz_seed_corpus.zip".
  seed_dir="$(mktemp -d)"
  SEED_DIR="$seed_dir" TARGET_NAME="$t" node -e "
    const { FUZZ_TARGETS } = require('./fuzz/targets.bundle.js');
    const fs = require('fs');
    const path = require('path');
    const t = FUZZ_TARGETS.find((x) => x.name === process.env.TARGET_NAME);
    (t ? t.seeds : []).forEach((s, i) =>
      fs.writeFileSync(path.join(process.env.SEED_DIR, String(i)), s));
  "
  ( cd "$seed_dir" && zip -q -r "$OUT/${t}.fuzz_seed_corpus.zip" . )
  rm -rf "$seed_dir"
done
