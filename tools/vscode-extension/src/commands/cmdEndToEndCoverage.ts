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
import {buildFuzzersFromWorkspace, runFuzzerHandler} from '../ossfuzzWrappers';
import {listFuzzersForProject, systemSync} from '../utils';
import {loadCoverageIntoWorkspace} from '../coverageHelper';
import {extensionConfig} from '../config';

/**
 * Performs the activities:
 * 1) Build a project using address sanitizer
 * 2) Run each fuzzer of the project, saving corpus
 * 3) Build project using coverage sanitizer
 * 4) Collect coverage
 * @param context
 * @returns
 */
export async function runEndToEndAndGetCoverage(
  context: vscode.ExtensionContext
) {
  println('Getting code coverage');
  const ossFuzzProjectNameInput = await vscode.window.showInputBox({
    value: '',
    placeHolder: 'The OSS-Fuzz project name',
  });
  if (!ossFuzzProjectNameInput) {
    println('Did not get a ossFuzzTargetProject');
    return;
  }
  const secondsToRunEachFuzzer = await vscode.window.showInputBox({
    value: '',
    placeHolder: 'Seconds to run each fuzzer',
  });
  if (!secondsToRunEachFuzzer) {
    println('Did not get number of seconds to run each fuzzer');
    return;
  }

  // Create an history object
  const args = new Object({
    projectName: ossFuzzProjectNameInput.toString(),
    secondsToRun: secondsToRunEachFuzzer.toString(),
    vsContext: context,
  });

  const commandObject = new Object({
    commandType: 'oss-fuzz.cmdDispatchEndToEndRun',
    Arguments: args,
    dispatcherFunc: cmdDispatchEndToEndRun,
  });
  console.log('L1: ' + commandHistory.length);
  commandHistory.push(commandObject);

  await cmdDispatchEndToEndRun(args);
  return;
}

async function cmdDispatchEndToEndRun(args: any) {
  await endToEndRun(args.projectName, args.secondsToRun, args.vsContext);
  return;
}

async function endToEndRun(
  ossFuzzProjectNameInput: string,
  secondsToRunEachFuzzer: string,
  context: vscode.ExtensionContext
) {
  vscode.window.showInformationMessage(
    'Building project: ' + ossFuzzProjectNameInput.toString()
  );
  if (await buildFuzzersFromWorkspace(ossFuzzProjectNameInput.toString(), '', true) == false) {
    println("Failed to build project");
    return;
  }
  println('Build projects');

  // List all of the fuzzers in the project
  const fuzzersInProject = await listFuzzersForProject(
    ossFuzzProjectNameInput,
    extensionConfig.ossFuzzPepositoryWorkPath
  );

  // Run all of the fuzzers in the project
  println('Fuzzers found in project: ' + fuzzersInProject.toString());
  println('Running each of the fuzzers to collect a corpus');
  for (const fuzzName of fuzzersInProject) {
    println('Running fuzzer: ' + fuzzName);
    // Corpus directory
    const fuzzerCorpusPath =
      extensionConfig.ossFuzzPepositoryWorkPath +
      '/build/corpus/' +
      ossFuzzProjectNameInput +
      '/' +
      fuzzName;

    await systemSync('mkdir', ['-p', fuzzerCorpusPath]);

    await runFuzzerHandler(
      ossFuzzProjectNameInput,
      fuzzName,
      secondsToRunEachFuzzer.toString(),
      fuzzerCorpusPath
    );
  }

  // Build with code coverage
  println('Building project with coverage sanitizer');
  await buildFuzzersFromWorkspace(
    ossFuzzProjectNameInput.toString(),
    'coverage',
    true
  );

  // Run coverage command
  println('Collecting code coverage');
  const args: Array<string> = [
    extensionConfig.ossFuzzPepositoryWorkPath + '/infra/helper.py',
    'coverage',
    '--port',
    '',
    '--no-corpus-download',
    ossFuzzProjectNameInput.toString(),
  ];
  await systemSync('python3', args);

  println('Load coverage report with the command:');
  println(
    'python3 -m http.server 8008 --directory /tmp/oss-fuzz/build/out/' +
      ossFuzzProjectNameInput.toString() +
      '/report/'
  );

  println('Trying to load code coverage in IDE');
  const allCovPath =
    extensionConfig.ossFuzzPepositoryWorkPath +
    '/build/out/' +
    ossFuzzProjectNameInput.toString() +
    '/textcov_reports/all_cov.json';
  if (fs.existsSync(allCovPath)) {
    const generatedCodeCoverageFile = vscode.Uri.file(allCovPath);
    await loadCoverageIntoWorkspace(context, generatedCodeCoverageFile);
  }
}
