// Copyright 2017 Google Inc. All Rights Reserved.
// Licensed under the Apache License, Version 2.0 (the "License");

// Simple unit test for DoStuff().
// This unit test does not cover the existing bug in DoStuff(),
// unless you pass an extra parameter ("BUG").
#include "my_api.h"

#include <cassert>
#include <iostream>

void TestDoStuff(const std::string &str, size_t Expected) {
  size_t Result = DoStuff(str);
  std::cerr << str << " => " << Result << std::endl;
  assert(Result == Expected);
}

int main(int argc, char **argv) {
  // Test some simple inputs, verify the output.
  TestDoStuff("", 0);
  TestDoStuff("foo", 1);
  TestDoStuff("omg", 1);
  TestDoStuff("bar", 1);
  TestDoStuff("ouch", 1);
  TestDoStuff("foobar", 3);
  TestDoStuff("foouchbar", 4);
  if (argc == 2 && std::string(argv[1]) == "BUG") {
    // This is the missing test that actually triggers the bug.
    TestDoStuff("foouchbaromg", 4);
  }
}
