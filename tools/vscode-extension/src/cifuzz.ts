// Copyright 2023 Google LLC
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
////////////////////////////////////////////////////////////////////////////////

import {println} from './logger';

/**
 * Creates a CIFuzz template
 * @param language
 * @param projectName
 * @param secondToRun
 * @returns
 */
export function cifuzzGenerator(
  language: string,
  projectName: string,
  secondToRun: Number
) {
  println('Exporting cifuzz logic ' + language);

  const cifuzzTemplate = `name: CIFuzz
on: [pull_request]
permissions: {}
jobs:
    Fuzzing:
    runs-on: ubuntu-latest
    permissions:
        security-events: write
    steps:
    - name: Build Fuzzers
        id: build
        uses: google/oss-fuzz/infra/cifuzz/actions/build_fuzzers@master
        with:
        oss-fuzz-project-name: '${projectName}'
        language: ${language}
    - name: Run Fuzzers
        uses: google/oss-fuzz/infra/cifuzz/actions/run_fuzzers@master
        with:
        oss-fuzz-project-name: '${projectName}'
        language: ${language}
        fuzz-seconds: ${secondToRun}
        output-sarif: true
    - name: Upload Crash
        uses: actions/upload-artifact@v3
        if: failure() && steps.build.outcome == 'success'
        with:
        name: artifacts
        path: ./out/artifacts
    - name: Upload Sarif
        if: always() && steps.build.outcome == 'success'
        uses: github/codeql-action/upload-sarif@v2
        with:
        # Path to SARIF file relative to the root of the repository
        sarif_file: cifuzz-sarif/results.sarif
        checkout_path: cifuzz-sarif`;

  return cifuzzTemplate;
}
