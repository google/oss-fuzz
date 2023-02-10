#!/bin/bash -eu
# Copyright 2022 Google LLC
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
# helm specifies Go 1.17 as the minimum Go version, and this causes go mod tidy
# to fail because Go 1.17 and Go 1.16 would select different versions of
# a dependency (github.com/mattn/go-isatty). By default, tidy acts as if
# the -compat flag were set to the version prior to the one indicated by
# the 'go' directive in the go.mod file.
#
# Since we use Go 1.19 to instrument the code, we patch the minimum version in go.mod.
sed -i 's/go 1.17/go 1.19/g' $SRC/helm/go.mod

$SRC/cncf-fuzzing/projects/helm/build.sh
