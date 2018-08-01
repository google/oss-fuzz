#!/usr/bin/python

import os
import sys
import re

fuzzer_target = sys.argv[1]
directory, fuzzer_target_name = os.path.dirname(fuzzer_target), os.path.basename(fuzzer_target)
path = os.path.join('..', 'envoy', directory, 'BUILD')

with open(path, 'r') as f:
  searchlines = f.readlines()
  for i, line in enumerate(searchlines):
      if fuzzer_target_name in line:
        for l in searchlines[i:]:
          if 'corpus =' in l:
            corpus_path = l
            break
try:
  corpus_path
except NameError:  
  raise Exception("No corpus path for the given fuzz target")
print re.findall(r'"([^"]*)"', corpus_path)[0]
