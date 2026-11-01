/* Copyright 2026 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <string>

#include "parser/options.h"
#include "parser/parser.h"
#include "eval/public/cel_expression.h"
#include "eval/public/cel_expr_builder_factory.h"
#include "eval/public/builtin_func_registrar.h"
#include "eval/public/activation.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size > 1024) return 0;
    std::string str (reinterpret_cast<const char*>(data), size);
    
    auto builder = google::api::expr::runtime::CreateCelExpressionBuilder();
    auto status = google::api::expr::runtime::RegisterBuiltinFunctions(builder->GetRegistry());
    if (!status.ok()) {
        return 0;
    }

    google::api::expr::parser::ParserOptions options;
    options.max_recursion_depth = 128;
    options.expression_size_codepoint_limit = 1 << 20;

    try {
        auto parse_status = google::api::expr::parser::Parse(str, "fuzzinput", options);
        if (!parse_status.ok()) {
            return 0;
        }

        auto expr_status = builder->CreateExpression(&parse_status->expr(), &parse_status->source_info());
        if (expr_status.ok()) {
            google::protobuf::Arena arena;
            google::api::expr::runtime::Activation activation;
            auto eval_status = (*expr_status)->Evaluate(activation, &arena);
        }
    } catch (const std::exception& e) {
        return 0;
    }
    return 0;
}
