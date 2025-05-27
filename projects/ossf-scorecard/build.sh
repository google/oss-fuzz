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



############################
# Here we write the the def.yml files to a variable in each probe.
# When the probes fuzzer runs, it writes the yaml to disk so Scorecard
# can read it from there. This is because Scorecard embeds the .yml
# files which is not supported when fuzzing.
find ./probes -type f -name 'def.yml' -exec bash -c '
    for file do
        dirPath=$(dirname $file)
        packageName=$(basename $dirPath)
        yaml_contents=$(cat $dirPath/def.yml)
        yaml_file_contents="package ${packageName}\n\nvar YmlFile=\`${yaml_contents//\`/}\`"
        echo -e "${yaml_file_contents}" >> "${dirPath}/def.go"
        gofmt -w "${dirPath}/def.go"
    done
' _ {} +

# Here we rewrite the path from which we read the def.yml file.
sed -i '19i "os"' finding/probe.go
sed -i 's|content, err := loc.ReadFile("def.yml")|content, err := os.ReadFile(fmt.Sprintf("/tmp/probedefinitions/%s/def.yml", probeID))|' finding/probe.go
gofmt -w finding/probe.go

# End of doing the workaround of the def.yml files.
#############################

mv $SRC/probes_fuzzer.go $SRC/scorecard/probes/
printf "package probes \nimport _ \"github.com/AdamKorcz/go-118-fuzz-build/testing\"\n" > ./probes/fuzz-register.go
go mod tidy
compile_native_go_fuzzer github.com/ossf/scorecard/v5/probes FuzzProbes FuzzProbes gofuzz

mv $SRC/yaml_fuzzer.go $SRC/scorecard/policy/
compile_go_fuzzer github.com/ossf/scorecard/v5/policy FuzzParseFromYAML fuzz_parse_from_yaml gofuzz
