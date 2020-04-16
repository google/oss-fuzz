################################################################################
# Copyright 2020 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################
cmake_minimum_required(VERSION 3.5)
project(pcl_fuzz_check)

find_package(PCL COMPONENTS io REQUIRED)

SET(LIB_FUZZING_ENGINE "" CACHE STRING "Location of static library for fuzzing")
add_library(libFuzz STATIC IMPORTED)
set_target_properties(libFuzz PROPERTIES IMPORTED_LOCATION ${LIB_FUZZING_ENGINE})

add_executable(png_fuzzer png.cpp)
target_link_libraries(pcl_demo ${PCL_LIBRARIES} libFuzz)
