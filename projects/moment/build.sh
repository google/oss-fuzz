#!/bin/bash -eu
npm install
npm install --save-dev @jazzer.js/core
compile_javascript_fuzzer moment fuzz.js -i moment --sync
