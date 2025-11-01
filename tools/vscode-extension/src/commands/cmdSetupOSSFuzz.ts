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

import {println} from '../logger';
import {extensionConfig} from '../config';
import {isPathValidOssFuzzPath} from '../ossfuzzWrappers';
import {systemSync} from '../utils';

/**
 * Function for setting up oss-fuzz. This clones the relevant directory
 * and sets the oss-fuzz variable accordingly.
 */
export async function setUpOssFuzzHandler() {
  println('Setting up oss-fuzz in /tmp/');

  // First check if we already have an OSS-Fuzz path
  const tmpOssFuzzRepositoryPath = '/tmp/oss-fuzz';

  if ((await isPathValidOssFuzzPath(tmpOssFuzzRepositoryPath)) === true) {
    println('OSS-Fuzz already exists in /tmp/oss-fuzz');
    extensionConfig.ossFuzzPepositoryWorkPath = tmpOssFuzzRepositoryPath;
    return;
  }

  const cmdToExec = 'git';
  const args: Array<string> = [
    'clone',
    'https://github.com/google/oss-fuzz',
    tmpOssFuzzRepositoryPath,
  ];
  const [res, output] = await systemSync(cmdToExec, args);
  if (res === false) {
    println('Failed to clone oss-fuzz');
    println(output);
    return;
  }
  println('Finished cloning oss-fuzz');

  extensionConfig.ossFuzzPepositoryWorkPath = tmpOssFuzzRepositoryPath;
}
