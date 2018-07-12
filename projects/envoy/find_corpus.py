#!/usr/bin/pxython

import os
import sys
import re

fuzzer_target = sys.argv[1].split("/")
(directory_segments, fuzz_test) = (fuzzer_target[:-1], fuzzer_target[-1])
directory = '/'.join(directory_segments)
path = '../envoy/' + directory + '/BUILD'
corpus_path = ""

with open(path, 'r') as f:
  searchlines = f.readlines()
  for (i, line) in enumerate(searchlines):
    if fuzz_test in line:
      for l in searchlines[i:]:
        if 'corpus =' in l:
          corpus_path = l
          break
if not corpus_path:
    raise Exception("No corpus path for the given fuzz target")
print re.findall(r'"([^"]*)"', corpus_path)[0]
