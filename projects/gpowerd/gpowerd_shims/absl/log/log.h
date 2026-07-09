// Copyright 2026 Google LLC
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
//
// Done.

#ifndef SHIM_ABSL_LOG_LOG_H_
#define SHIM_ABSL_LOG_LOG_H_

#include <iostream>

#define LOG(severity) std::cerr << #severity << ": "
#define LOG_IF(severity, condition) if (condition) std::cerr << #severity << ": "
#define LOG_EVERY_N(severity, n) std::cerr << #severity << ": "
#define LOG_FIRST_N(severity, n) std::cerr << #severity << ": "
#define LOG_EVERY_N_SEC(severity, n) std::cerr << #severity << ": "
#define DLOG(severity) std::cerr << #severity << ": "
#define VLOG(severity) std::cerr << "V" << severity << ": "
#define DFATAL FATAL

#endif  // SHIM_ABSL_LOG_LOG_H_
