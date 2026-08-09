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


#include <chrono>
#include <cstdint>
#include <string>

#define exprtk_enable_range_runtime_checks
#include "exprtk.hpp"


constexpr auto max_test_duration = std::chrono::seconds(58); // OSSFuzz test time is 60seconds
const     auto global_timeout_tp = std::chrono::steady_clock::now() + max_test_duration;

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

   void handle_runtime_violation(const violation_context& /*context*/) override
   {
      throw timeout_exception("ExprTk Loop run-time timeout violation.");
   }

   std::size_t iterations_ = 0;
   time_point_t timeout_tp_;
};

struct compilation_timeout_check final : public exprtk::compilation_check
{
   static constexpr std::size_t max_iters_per_check = 500;

   bool continue_compilation(compilation_context& context) override
   {
      if (++iterations_ >= max_iters_per_check)
      {
         if (std::chrono::steady_clock::now() >= timeout_tp_)
         {
            context.error_message = "Compilation has timed-out";
            return false;
         }

         iterations_ = 0;
      }

      return true;
   }

   using time_point_t = std::chrono::time_point<std::chrono::steady_clock>;

   void set_timeout_time(const time_point_t& timeout_tp)
   {
      timeout_tp_ = timeout_tp;
   }

   std::size_t iterations_ = max_iters_per_check;
   time_point_t timeout_tp_;
};

struct vector_access_rtc final : public exprtk::vector_access_runtime_check
{
   bool handle_runtime_violation(violation_context& /*context*/) override
   {
      throw std::runtime_error("Runtime vector access violation.");
      return false;
   }
};

struct assert_handler final : public exprtk::assert_check
{
   void handle_assert(const assert_context& /*context*/) override
   {
      throw std::runtime_error("assert: vector access violation.");
   }
};

template <typename T>
void run(const std::string& expression_string)
{
   using symbol_table_t       = exprtk::symbol_table<T>;
   using expression_t         = exprtk::expression<T>;
   using parser_t             = exprtk::parser<T>;
   using loop_runtime_check_t = exprtk::loop_runtime_check;

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

   compilation_timeout_check compilation_timeout_chck;
   vector_access_rtc         vector_rtc;
   assert_handler            asrt_handler;

   parser_t parser;

   parser.settings().set_max_stack_depth(400);
   parser.settings().set_max_node_depth (400);
   parser.settings().set_max_local_vector_size(10000000); // double: 80MB float: 40MB

   parser.register_compilation_timeout_check  (compilation_timeout_chck);
   parser.register_loop_runtime_check         (loop_runtime_check      );
   parser.register_vector_access_runtime_check(vector_rtc              );
   parser.register_assert_check               (asrt_handler            );

   compilation_timeout_chck.set_timeout_time(global_timeout_tp);

   if (parser.compile(expression_string, expression))
   {
      const std::size_t max_expression_size = 64 * 1024;

      if (expression_string.size() <= max_expression_size)
      {
         loop_runtime_check.set_timeout_time(global_timeout_tp);

         try
         {
            expression.value();
         }
         catch (std::runtime_error& rte)
         {}
         catch (...)
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
