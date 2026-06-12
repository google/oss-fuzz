#!/bin/bash -eu
npm install
npm install --save-dev @jazzer.js/core
compile_javascript_fuzzer jquery fuzz.js -i jquery --sync
