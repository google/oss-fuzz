/* Copyright 2025 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <cctype>
#include "CLI/CLI.hpp"

static std::vector<std::string> tokenize_ws(const std::string& s) {
  std::vector<std::string> out; std::string cur;
  for (unsigned char c : s) {
    if (std::isspace(c)) { if (!cur.empty()) { out.push_back(cur); cur.clear(); if (out.size() >= 64) break; } }
    else { if (cur.size() < 256) cur.push_back(static_cast<char>(c)); }
  }
  if (!cur.empty() && out.size() < 64) out.push_back(cur);
  return out;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size == 0 || size > (1<<16)) return 0;
  std::string s(reinterpret_cast<const char*>(data), size);
  auto args = tokenize_ws(s);

  std::vector<std::string> argv_strings; argv_strings.reserve(args.size()+1);
  argv_strings.emplace_back("prog"); for (auto& a: args) argv_strings.push_back(a);
  std::vector<char*> argv; for (auto& a: argv_strings) argv.push_back(a.data());
  int argc = static_cast<int>(argv.size());

  CLI::App app("fuzz");
  int i=0, si=0; double d=0; bool b=false;
  std::vector<int> ints; std::vector<std::string> strs, sstrs;
  app.add_option("-i,--int", i);
  app.add_option("-d,--double", d);
  app.add_flag("-b,--bool", b);
  app.add_option("-n,--ints", ints)->take_all();
  app.add_option("-s,--str",  strs)->take_all();
  app.allow_extras(true);
  auto sub = app.add_subcommand("sub", "subcommand");
  sub->add_option("--si", si);
  sub->add_option("--sstr", sstrs)->take_all();
  try { app.parse(argc, argv.data()); } catch (const CLI::ParseError&) {} catch (...) {}
  return 0;
}
