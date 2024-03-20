/*
 * Copyright 2023 Google LLC

 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at

 *      http://www.apache.org/licenses/LICENSE-2.0

 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#if defined(__aarch64__)
#define REGS_SYSCALL regs.regs[8]
#define REGS_ARG1 regs.regs[0]
#define REGS_ARG2 regs.regs[1]
#define REGS_ARG3 regs.regs[2]
#elif defined(__x86_64__)
#define REGS_SYSCALL regs.orig_rax
#define REGS_ARG1 regs.rdi
#define REGS_ARG2 regs.rsi
#define REGS_ARG3 regs.rdx
#endif