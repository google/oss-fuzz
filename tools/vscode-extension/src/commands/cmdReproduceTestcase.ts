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

import * as vscode from 'vscode';
const fs = require('fs');
import {println} from '../logger';
import {commandHistory} from '../commandUtils';
import {systemSyncLogIfFailure} from '../utils';
import {buildFuzzersFromWorkspace} from '../ossfuzzWrappers';
import {extensionConfig} from '../config';
const readline = require('readline');


export async function cmdInputCollectorReproduceTestcase() {
  // Runs a fuzzer from a given project.
  const crashFileInput = await vscode.window.showInputBox({
    value: '',
    placeHolder: 'The ID of the testcase.',
  });
  if (!crashFileInput) {
    return;
  }
  // Create an history object and append it to the command history.
  const args = new Object({
    crashFile: crashFileInput.toString(),
  });

  const commandObject = new Object({
    commandType: 'oss-fuzz.ReproduceFuzzer',
    Arguments: args,
    dispatcherFunc: cmdDispatchReproduceTestcase,
  });
  commandHistory.push(commandObject);

  await cmdDispatchReproduceTestcase(args);
  return true;
}

async function cmdDispatchReproduceTestcase(args: any) {
  await reproduceTestcase(args.crashFile);
}

export async function reproduceTestcase(crashInfoFileInput: string) {
  println('Reproducing testcase for ' + crashInfoFileInput);
  println('Checking directory: ' + extensionConfig.crashesDirectory);

  const crashInfoFile =
    extensionConfig.crashesDirectory + '/' + crashInfoFileInput + '.info';
  println(crashInfoFile);
  try {
    if (fs.existsSync(crashInfoFile)) {
      println('File exists');
    } else {
      println('Crash file does not exist');
      return;
    }
  } catch (err) {
    console.error(err);
    return;
  }

  // At this point the file exists
  const r = readline.createInterface({
    input: fs.createReadStream(crashInfoFile),
  });

  let targetProject = 'N/A';
  let targetFuzzer = 'N/A';
  // Logic for passing the file. This is based off of clusterfuzz monorail reports,
  // and the intention is the file needs to be a copy of:
  //
  // Project: project-name
  // Fuzzing Engine: libFuzzer
  // Fuzz Target: fuzzer-name
  //
  // Example:
  // The following URL: https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=59747
  // has the bug information:
  // """
  // Project: my-fuzzing-project
  // Fuzzing Engine: libFuzzer
  // Fuzz Target: the-fuzzer-name-fuzz-parseXX
  // Job Type: libfuzzer_asan_my-fuzzing-project
  // Platform Id: linux
  // """
  // and a link to a reproducer test case:
  // https://oss-fuzz.com/download?testcase_id=5009071179431936
  // which, when accessed will download the file
  // clusterfuzz-testcase-minimized-flb-it-fuzz-config_map_fuzzer_OSSFUZZ-5009071179431936
  //
  // To enable reproducing of this issue we need to:
  // - 1) Download the crash file and place it in the directory given in config.ts
  //      and "crashesDirectory" variable.
  // - 2) create a file "5009071179431936.info" and paste the information above
  //      (Project:... Fuzz Target: ...) into the file. This information is
  //      needed because we need to know project name and fuzzer name in order
  //      to reproduce the crash.
  // - 3) the reproducer can now be reproduced using the reproduce command
  //      with argument "5009071179431936" as argument.
  r.on('line', (text: string) => {
    println(text);
    if (text.startsWith('Project: ')) {
      println('Starts with project');
      println(text.split('Project: ').toString());
      targetProject = text.split('Project: ')[1];
    } else if (text.startsWith('Fuzzing Engine: ')) {
      println('Starts with fuzzing engine');
    } else if (text.startsWith('Fuzz Target:')) {
      println('Starts with Fuzz Target');
      targetFuzzer = text.split('Fuzz Target: ')[1];
    } else if (text.startsWith('Job Type:')) {
      println('Starts with Job Type');
    }
  });

  r.on('close', async () => {
    println('Target project: ' + targetProject);
    println('Target fuzzer: ' + targetFuzzer);

    // Build a fresh version of the project.
    const buildResult: boolean = await buildFuzzersFromWorkspace(
      targetProject,
      '',
      true
    );
    if (!buildResult) {
      println('Failed to build fuzzers');
      return false;
    }

    // We have a fresh build of the project, proceed to reproduce the testcase.
    const crashInputTestCase =
      extensionConfig.crashesDirectory +
      '/' +
      'clusterfuzz-testcase-minimized-' +
      targetFuzzer +
      '-' +
      crashInfoFileInput;
    // Run reproduce command against the target file
    // Build the fuzzers using OSS-Fuzz infrastructure.
    const cmdToExec = 'python3';
    const args = [
      extensionConfig.ossFuzzPepositoryWorkPath + '/infra/helper.py',
      'reproduce',
      targetProject,
      targetFuzzer,
      crashInputTestCase,
    ];
    if (!(await systemSyncLogIfFailure(cmdToExec, args))) {
      println('Failed to reproduce testcase');
    }

    return true;
  });
}
