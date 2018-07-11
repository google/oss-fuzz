#!/usr/bin/python
import os, sys, re
fuzzer_target = sys.argv[1].split('/')
directory, fuzz_test = fuzzer_target[:-1], fuzzer_target[-1]
directory_string = "/".join(directory)
path = "../envoy/" + directory_string + "/BUILD"
with open(path, "r") as f:
        searchlines = f.readlines()
        for i, line in enumerate(searchlines):
                if fuzz_test in line: 
                    for l in searchlines[i:]:
                        if "corpus =" in l:
                              corpus_path = l 
                              break
print re.findall(r'"([^"]*)"', corpus_path)[0]
