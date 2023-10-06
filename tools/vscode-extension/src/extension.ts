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

import {clearCoverage} from './coverageHelper';
import {println} from './logger';

// Import the command dispatcher functions
import {cmdInputCollectorRunSpecificFuzzer} from './commands/cmdRunFuzzer';
import {cmdInputCollectorBuildFuzzersFromWorkspace} from './commands/cmdBuildFuzzerFromWorkspace';
import {cmdDispatcherRe} from './commands/cmdRedo';
import {setupCIFuzzHandler} from './commands/cmdSetupCIFuzz';
import {cmdInputCollectorTestFuzzer} from './commands/cmdTestFuzzer';
import {displayCodeCoverageFromOssFuzz} from './commands/cmdDisplayCoverage';
import {createOssFuzzSetup} from './commands/cmdCreateOSSFuzzSetup';
import {runEndToEndAndGetCoverage} from './commands/cmdEndToEndCoverage';
import {listFuzzersHandler} from './commands/cmdListFuzzers';
import {cmdInputCollectorReproduceTestcase} from './commands/cmdReproduceTestcase';
import {cmdDispatcherTemplate} from './commands/cmdTemplate';
import {setUpOssFuzzHandler} from './commands/cmdSetupOSSFuzz';
import {setOssFuzzPath} from './commands/cmdSetOSSFuzzPath';
import {extensionConfig} from './config';

/**
 * Extension entrypoint. Activate the extension and register the commands.
 */
export function activate(context: vscode.ExtensionContext) {
  console.log('Activating extension)');
  extensionConfig.printConfig();
  println('OSS-Fuzz extension is now active!');

  // Command registration
  context.subscriptions.push(
    vscode.commands.registerCommand('oss-fuzz.SetUp', async () => {
      println('CMD start: SetUp');
      await setUpOssFuzzHandler();
      println('CMD end: SetUp');
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('oss-fuzz.RunFuzzer', async () => {
      println('CMD start: Run Fuzzer');
      //await runFuzzerHandler('', '', '', '');
      cmdInputCollectorRunSpecificFuzzer();
      println('CMD end: Run Fuzzer');
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('oss-fuzz.ListFuzzers', async () => {
      println('CMD start: ListFuzzers');
      await listFuzzersHandler();
      println('CMD end: ListFuzzers');
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('oss-fuzz.SetOSSFuzzPath', async () => {
      println('CMD start: SetOSSFuzzPath');
      await setOssFuzzPath();
      println('CMD end: SetOSSFuzzPath');
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('oss-fuzz.GetCodeCoverage', async () => {
      println('CMD start: GetCodeCoverage');
      await displayCodeCoverageFromOssFuzz(context);
      println('CMD end: GetCodeCoverage');
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('oss-fuzz.ClearCodeCoverage', async () => {
      println('CMD start: ClearCodeCoverage');
      await clearCoverage();
      println('CMD end: ClearCodeCoverage');
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('oss-fuzz.CreateOSSFuzzSetup', async () => {
      println('CMD start: CreateOSSFuzzSetup');
      await createOssFuzzSetup();
      println('CMD end: CreateOSSFuzzSetup');
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('oss-fuzz.WSBuildFuzzers', async () => {
      println('CMD start: WSBuildFuzzers3');
      await cmdInputCollectorBuildFuzzersFromWorkspace();
      println('CMD end: WSBuildFuzzers4');
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('oss-fuzz.SetupCIFuzz', async () => {
      println('CMD start: SetupCIFuzz');
      await setupCIFuzzHandler();
      println('CMD end: SetupCIFuzz');
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('oss-fuzz.testFuzzer', async () => {
      println('CMD start: testFuzzer');
      await cmdInputCollectorTestFuzzer();
      println('CMD end: testFizzer');
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('oss-fuzz.testCodeCoverage', async () => {
      println('CMD start: testCodeCoverage');
      await runEndToEndAndGetCoverage(context);
      println('CMD end: testCodeCoverage');
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('oss-fuzz.Reproduce', async () => {
      println('CMD start: Reproduce');
      await cmdInputCollectorReproduceTestcase();
      println('CMD end: Reproduce');
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('oss-fuzz.Redo', async () => {
      println('CMD start: Re');
      await cmdDispatcherRe();
      println('CMD end: Re');
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('oss-fuzz.Template', async () => {
      println('CMD start: remplate');
      await cmdDispatcherTemplate(context);
      println('CMD end: template');
    })
  );
}

// This method is called when your extension is deactivated
export function deactivate() {
  println('Deactivating the extension');
}
