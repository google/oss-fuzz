// Copyright 2024 Google LLC
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
 * Function for setting up Fuzz Introspector by way of a Python virtual env.
 */
export async function setUpFuzzIntrospectorHandler() {
  println('Setting up oss-fuzz in /tmp/');

  // First check if we already have Fuzz Introspector installed.
  const tmpOssFuzzRepositoryPath = '/tmp/fi-tmp-env';

  if ((await isPathValidOssFuzzPath(tmpOssFuzzRepositoryPath)) === true) {
    println('Fuzz Introspector virtual env already exists in /tmp/fi-tmp-env');
    extensionConfig.ossFuzzPepositoryWorkPath = tmpOssFuzzRepositoryPath;
    return;
  }

  const cmdToExec = 'python3.11';
  const args: Array<string> = ['-m', 'virtualenv', tmpOssFuzzRepositoryPath];
  const [res, output] = await systemSync(cmdToExec, args);
  if (res === false) {
    println('Failed to create virtual environment');
    println(output);
    return;
  }

  const cmdToExec2 = '/tmp/fi-tmp-env/bin/python3.11';
  const args2: Array<string> = [
    '-m',
    'pip',
    'install',
    'fuzz-introspector==0.1.4',
  ];
  const [res2, output2] = await systemSync(cmdToExec2, args2);
  if (res2 === false) {
    println('Failed to create virtual environment');
    println(output2);
    return;
  }
}
