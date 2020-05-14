#include <stdint.h>
#include <stdio.h>
#include <iostream>
#include <string>
#include "muParser.h"
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  std::string line_string((char *)data, size);
  try {
    mu::Parser parser;
    parser.SetExpr(line_string);
    parser.Eval();
  } catch (mu::Parser::exception_type &e) {
     std::cout << e.GetMsg() << std::endl;
  }
  return 0;
}
