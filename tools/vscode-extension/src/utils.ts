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
import {extensionConfig} from './config';
import {getApi, FileDownloader} from '@microsoft/vscode-file-downloader-api';

const fs = require('fs');
const {spawn} = require('node:child_process');

import {println, printRaw, debugPrintln} from './logger';

export async function downloadRemoteURL(
  urlString: string,
  targetFile: string,
  context: vscode.ExtensionContext
) {
  const fileDownloader: FileDownloader = await getApi();
  //var urlString = await getOSSFuzzCloudURL(projectName) + '/linux/summary.json';

  println('URL: ' + urlString);
  let codeCoverageFile: vscode.Uri;
  try {
    codeCoverageFile = await fileDownloader.downloadFile(
      vscode.Uri.parse(urlString),
      targetFile,
      context
    );
  } catch (err) {
    println('Could not get the coverage summary file');
    return false;
  }
  return codeCoverageFile;
}

export async function getLocalOutBuildDir(projectName: string) {
  const summaryCovPath =
    extensionConfig.ossFuzzPepositoryWorkPath + '/build/out/' + projectName;
  return summaryCovPath;
}

export async function getOSSFuzzCloudURL(projectName: string) {
  const currentDate = new Date();
  const yesterday = new Date(currentDate);
  yesterday.setDate(yesterday.getDate() - 1);

  const day = yesterday.getDate();
  const month = yesterday.getMonth();
  const year = yesterday.getFullYear();

  let urlString =
    'https://storage.googleapis.com/oss-fuzz-coverage/' +
    projectName +
    '/reports/' +
    year.toString();

  if (month < 10) {
    urlString += '0';
  }
  urlString += month.toString();
  if (day < 10) {
    urlString += '0';
  }
  urlString += day.toString();

  return urlString;
}

/**
 * Checks if the current workspace has a generated OSS-Fuzz folder. This is the
 * generated folder from our auto-generation capabilities.
 *
 * @returns boolean
 */
export async function hasOssFuzzInWorkspace() {
  const workspaceFolder = vscode.workspace.workspaceFolders;

  if (!workspaceFolder) {
    return false;
  }

  // Identify if the workspace folder has a OSS-Fuzz set up.
  const wsPath = workspaceFolder[0].uri.fsPath; // gets the path of the first workspace folder
  const ossfuzzDockerFilepath = vscode.Uri.file(wsPath + '/OSS-Fuzz/');
  try {
    if (await vscode.workspace.fs.readDirectory(ossfuzzDockerFilepath)) {
      for (const [name, type] of await vscode.workspace.fs.readDirectory(
        ossfuzzDockerFilepath
      )) {
        // If it's a directory then we know we have the project set up in there.
        if (type === 2) {
          // We assume this is the project folder for now.
          println('Found the relevant directory: ' + name);
          return true;
        }
      }
    }
  } catch {
    /* empty */
  }
  return false;
}

/**
 * Gets the project name of the integrated OSS-Fuzz project.
 * @returns string
 */
export async function getOssFuzzWorkspaceProjectName() {
  const workspaceFolder = vscode.workspace.workspaceFolders;
  if (!workspaceFolder) {
    return 'N/A';
  }

  // Identify if the workspace folder has a OSS-Fuzz set up.
  const wsPath = workspaceFolder[0].uri.fsPath; // gets the path of the first workspace folder
  const ossfuzzDockerFilepath = vscode.Uri.file(wsPath + '/OSS-Fuzz/');
  try {
    if (await vscode.workspace.fs.readDirectory(ossfuzzDockerFilepath)) {
      for (const [name, type] of await vscode.workspace.fs.readDirectory(
        ossfuzzDockerFilepath
      )) {
        if (type === 2) {
          // println('Is a directory');
          // We assume this is the project folder for now.
          return name;
        }
      }
    }
  } catch {
    /* empty */
  }

  return 'N/A';
}

/**
 * Lists the fuzzers available in the OSS-Fuzz build project.
 *
 * @param projectName
 * @param ossFuzzRepositoryPath
 * @returns
 */
export async function listFuzzersForProject(
  projectName: string,
  ossFuzzRepositoryPath: string
) {
  const projectOssFuzzBuildPath = vscode.Uri.file(
    ossFuzzRepositoryPath + '/build/out/' + projectName
  );
  const fuzzersInProject: Array<string> = [];
  for (const [name, type] of await vscode.workspace.fs.readDirectory(
    projectOssFuzzBuildPath
  )) {
    // Is it a file?
    if (type === 1) {
      const filepath =
        ossFuzzRepositoryPath + '/build/out/' + projectName + '/' + name;
      const binary = fs.readFileSync(filepath);

      // Check if fuzzer entrypoint exists in file. This is similar to how OSS-Fuzz
      // checks whether a file is fuzzer or not.
      if (binary.lastIndexOf('LLVMFuzzerTestOneInput') !== -1) {
        fuzzersInProject.push(name);
      }
    }
  }
  println('Successfully build the project.');
  println('The fuzzers in project');
  for (const fuzzName of fuzzersInProject) {
    println(fuzzName);
  }
  return fuzzersInProject;
}

/**
 * Helper functions for identifying the primary programming language of the workspace.
 *
 * This is achieved by identifying the suffix of files and then sorting
 * based on those with most of a given language supported by OSS-Fuzz.
 *
 * @returns
 */
export async function determineWorkspaceLanguage() {
  const pythonFiles = await vscode.workspace.findFiles('**/*.py');
  const cppFiles = await vscode.workspace.findFiles('**/*.c++');
  const cfiles = await vscode.workspace.findFiles('**/*.c');
  const rustFiles = await vscode.workspace.findFiles('**/*.rust');
  const golangFiles = await vscode.workspace.findFiles('**/*.go');

  println('Number of python files: ' + pythonFiles.length);
  println('Number of C++ files: ' + cppFiles.length);
  println('Number of C files: ' + cfiles.length);
  println('Number of rustFiles files: ' + rustFiles.length);
  println('Number of golangFiles files: ' + golangFiles.length);

  const maxCount = Math.max(
    pythonFiles.length,
    cppFiles.length,
    cfiles.length,
    rustFiles.length,
    golangFiles.length
  );
  let target = '';
  if (maxCount === pythonFiles.length) {
    target = 'python';
  } else if (maxCount === cppFiles.length) {
    target = 'c++';
  } else if (maxCount === cfiles.length) {
    target = 'c';
  } else if (maxCount === rustFiles.length) {
    target = 'rust';
  } else if (maxCount === golangFiles.length) {
    target = 'golang';
  } else {
    target = 'not implemented';
  }

  println('Target language: ' + target);
  return target;
}

/**
 * Helper method to execute commands on the system.
 */
export async function systemSync(cmd: string, args: Array<string | undefined>) {
  debugPrintln('Running command');
  debugPrintln(cmd);
  debugPrintln(args.toString());
  debugPrintln('<<<<<<<<<<<<');

  // Launch the command
  const command = spawn(cmd, args);

  // Callbacks for output events, to capture stdout and stderr live.
  command.stdout.on('data', (x: {toString: () => string}) => {
    printRaw(x.toString());
  });
  command.stderr.on('data', (x: {toString: () => string}) => {
    printRaw(x.toString());
  });

  // Monitor for child exit.
  let hasChildExited = 0;
  let childExitCode = 0;
  command.on('exit', (code: any, signal: any) => {
    // println('child process exited with ' + `code ${code} and signal ${signal}`);
    childExitCode = code;
    hasChildExited = 1;
  });

  // Block until the child process has exited.
  const snooze = (ms: number) =>
    new Promise(resolve => setTimeout(resolve, ms));

  let idx = 0;
  const maxSeconds = 1800;
  debugPrintln('Child exited: ' + hasChildExited);

  // I think we can convert the following loop to a Promise wrapping the command
  // exeuction. TODO(David).
  while (hasChildExited === 0 && idx < maxSeconds) {
    idx += 1;
    await snooze(1000);
  }

  // Command execution is done, return appropriately if success/error.
  if (childExitCode !== 0) {
    println('Command execution errored');
    return [false, command.toString()];
  }
  // println('Succes');
  return [true, command.toString()];
}

export async function systemSyncLogIfFailure(
  cmd: string,
  args: Array<string | undefined>
): Promise<boolean> {
  const [res, cmdMsg] = await systemSync(cmd, args);
  if (res === false) {
    println(cmdMsg);
    return false;
  }
  return true;
}
