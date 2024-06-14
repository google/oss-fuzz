/* # Copyright 2020 Google Inc. */
/* # */
/* # Licensed under the Apache License, Version 2.0 (the "License"); */
/* # you may not use this file except in compliance with the License. */
/* # You may obtain a copy of the License at */
/* # */
/* #      http://www.apache.org/licenses/LICENSE-2.0 */
/* # */
/* # Unless required by applicable law or agreed to in writing, software */
/* # distributed under the License is distributed on an "AS IS" BASIS, */
/* # WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. */
/* # See the License for the specific language governing permissions and */
/* # limitations under the License. */
/* # */
/* ################################################################################ */

/*
 *  'fuzz_common' aims to provide some common functions for all fuzz target
 */

#pragma once

#define SUBSAMPLE(v, a) ((((v) + (a)-1)) / (a))

void write_conf(int width, int height, int cpu_flags, int src_stride_y, int src_stride_uv, int dst_stride_y, int dst_uv_stride);

int generate_cpuflags(int random_num);