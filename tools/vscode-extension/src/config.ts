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

export class ExtensionConfig {
  /** Path to the repository that will be used. */
  ossFuzzPepositoryWorkPath: string = '/tmp/oss-fuzz';

  /** The directory where crash info is stored. */
  crashesDirectory = process.env.HOME + '/oss-fuzz-crashes';

  /** Number of seconds used for running quick test fuzzers */
  numberOfSecondsForTestRuns = 20;

  async printConfig() {
    println('Config:');
    println('- OSS-Fuzz repository path: ' + this.ossFuzzPepositoryWorkPath);
    println('- Crashes directory: ' + this.crashesDirectory);
    println('- numberOfSecondsForTestRuns: ' + this.numberOfSecondsForTestRuns);
  }
}

export const extensionConfig = new ExtensionConfig();
