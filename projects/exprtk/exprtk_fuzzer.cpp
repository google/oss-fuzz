// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <cstdint>
#include <string>

#define exprtk_enable_range_runtime_checks
#include "exprtk.hpp"


template <typename T>
void run(const std::string& expression_string)
{
   typedef exprtk::symbol_table<T>    symbol_table_t;
   typedef exprtk::expression<T>      expression_t;
   typedef exprtk::parser<T>          parser_t;
   typedef exprtk::loop_runtime_check loop_runtime_check_t;

   T x = T(1.2345);
   T y = T(2.2345);
   T z = T(3.2345);
   T w = T(4.2345);

   symbol_table_t symbol_table;
   symbol_table.add_variable("x",x);
   symbol_table.add_variable("y",y);
   symbol_table.add_variable("z",z);
   symbol_table.add_variable("w",w);
   symbol_table.add_constants();

   expression_t expression;
   expression.register_symbol_table(symbol_table);

   loop_runtime_check_t loop_runtime_check;
   loop_runtime_check.loop_set = loop_runtime_check_t::e_all_loops;
   loop_runtime_check.max_loop_iterations = 100000;

   parser_t parser;

   parser.register_loop_runtime_check(loop_runtime_check);

   if (parser.compile(expression_string, expression))
   {
      const std::size_t max_expression_size = 64 * 1024;

      if (expression_string.size() <= max_expression_size)
      {
         try
         {
            expression.value();
         }
         catch (std::runtime_error& rte)
         {}

         parser.clear_loop_runtime_check();
      }
   }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
   const std::string expression(reinterpret_cast<const char*>(data), size);

   run<double>(expression);
   run<float> (expression);

   return 0;
}
