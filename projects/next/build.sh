#!/bin/bash -eu
npm install
npm install --save-dev @jazzer.js/core
compile_javascript_fuzzer next fuzz.js -i next --sync
