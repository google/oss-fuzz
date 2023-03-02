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
#include <chrono>
#include <string>

#define exprtk_enable_range_runtime_checks
#include "exprtk.hpp"

struct timeout_rtc_handler : public exprtk::loop_runtime_check
{
   timeout_rtc_handler()
   : exprtk::loop_runtime_check()
   {}

   class timeout_exception : public std::runtime_error
   {
   public:
       timeout_exception(const std::string& what = "")
       : std::runtime_error(what)
       {}
   };

   static constexpr std::size_t max_iterations = 5000000;

   using time_point_t = std::chrono::time_point<std::chrono::steady_clock>;

   void set_timeout_time(const time_point_t& timeout_tp)
   {
      timeout_tp_ = timeout_tp;
   }

   bool check() override
   {
      if (++iterations_ >= max_iterations)
      {
         if (std::chrono::steady_clock::now() >= timeout_tp_)
         {
            return false;
         }
         iterations_ = 0;
      }

      return true;
   }

   void handle_runtime_violation(const violation_context& ctx) override
   {
      throw timeout_exception("ExprTk Loop run-time timeout violation.");
   }

   std::size_t iterations_ = 0;
   time_point_t timeout_tp_;
};

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

   timeout_rtc_handler loop_runtime_check;
   loop_runtime_check.loop_set = loop_runtime_check_t::e_all_loops;
   loop_runtime_check.max_loop_iterations = 100000;

   parser_t parser;

   parser.register_loop_runtime_check(loop_runtime_check);

   if (parser.compile(expression_string, expression))
   {
      const std::size_t max_expression_size = 64 * 1024;

      if (expression_string.size() <= max_expression_size)
      {
         const auto max_duration = std::chrono::seconds(25);
         const auto timeout_tp = std::chrono::steady_clock::now() + max_duration;
         loop_runtime_check.set_timeout_time(timeout_tp);

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
