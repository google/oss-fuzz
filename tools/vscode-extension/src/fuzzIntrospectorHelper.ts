// Copyright 2025 Google LLC
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

import * as vscode from 'vscode';

import {println} from './logger';
import {extensionConfig} from './config';
import {isPathValidOssFuzzPath} from './ossfuzzWrappers';
import {systemSync} from './utils';

const fs = require('fs');

export async function setUpFuzzIntrospector() {
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
    'fuzz-introspector==0.1.6',
  ];
  const [res2, output2] = await systemSync(cmdToExec2, args2);
  if (res2 === false) {
    println('Failed to create virtual environment');
    println(output2);
    return;
  }
}

export async function runFuzzIntrospector() {
  println('Setting up oss-fuzz in /tmp/');

  const workspaceFolder = vscode.workspace.workspaceFolders;
  if (!workspaceFolder) {
    return;
  }
  const pathOfLocal = workspaceFolder[0].uri.fsPath;
  println('path of local: ' + pathOfLocal);

  // First check if we already have Fuzz Introspector installed.
  const tmpOssFuzzRepositoryPath = '/tmp/fi-tmp-env';

  if ((await isPathValidOssFuzzPath(tmpOssFuzzRepositoryPath)) === true) {
    println('Fuzz Introspector virtual env already exists in /tmp/fi-tmp-env');
    extensionConfig.ossFuzzPepositoryWorkPath = tmpOssFuzzRepositoryPath;
    return;
  }

  await systemSync('mkdir', ['-p', '/tmp/out-fi/']);

  const cmdToExec = '/tmp/fi-tmp-env/bin/fuzz-introspector';
  const args: Array<string> = [
    'full',
    '--target_dir=' + pathOfLocal,
    '--out-dir=/tmp/out-fi',
  ];
  const [res, output] = await systemSync(cmdToExec, args);
  if (res === false) {
    println('Failed run FI');
    println(output);
    return;
  }
}

export async function getOptimalTargetsFromIntrospector() {
  if (!fs.existsSync('/tmp/out-fi/summary.json')) {
    println('There are no introspector reports. Please run introspector first');
  }
  const json_data = fs.readFileSync('/tmp/out-fi/summary.json');
  // println(json_data);

  const jsonCodeCoverage = JSON.parse(json_data);

  println('Optimal targets');
  Object.entries(jsonCodeCoverage['analyses']['OptimalTargets']).forEach(
    entry => {
      const [key, value] = entry;
      const objectDictionary: any = value as any;
      println(JSON.stringify(objectDictionary, null, 2));
    }
  );
  println('--------------------------');

  return;
}
