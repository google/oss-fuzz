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

const fs = require('fs');
import * as vscode from 'vscode';
import {
  hasOssFuzzInWorkspace,
  getOssFuzzWorkspaceProjectName,
  listFuzzersForProject,
  systemSyncLogIfFailure,
} from './utils';
import {println} from './logger';
import {extensionConfig} from './config';

/**
 * Builds the fuzzers for a given workspace.
 *
 * There are two options:
 *  1) The fuzzers are build using the OSS-Fuzz set up in the folder
 *  2) The fuzzers are build using the workspace and then copies that over.
 */
export async function buildFuzzersFromWorkspace(
  projectNameArg: string,
  sanitizer: string,
  toClean: boolean
) {
  // println('Building fuzzers locally2');

  // Check if there is an OSS-Fuzz set up, and exit if not.
  if (
    (await isPathValidOssFuzzPath(
      extensionConfig.ossFuzzPepositoryWorkPath
    )) === false
  ) {
    println('No valid oss-fuzz path');
    return false;
  }

  const workspaceFolder = vscode.workspace.workspaceFolders;
  if (!workspaceFolder) {
    println('No workspace folder, exiting');
    return false;
  }

  let ossFuzzProjectName = '';
  if (await hasOssFuzzInWorkspace()) {
    /**
     * The fuzzers are in the workspace, as opposed to e.g. the oss-fuzz dirctory.
     */
    ossFuzzProjectName = await getOssFuzzWorkspaceProjectName();

    /**
     * The workspace has an OSS-Fuzz directory. We use this for the build.
     * This is done by copying over the relevant files to the oss-fuzz repository
     * folder. Notice that we will do a forceful copy overwriting the existing
     * project foler if it exists.
     */
    println('Found project folder: ' + ossFuzzProjectName);

    // Copy over the workspace oss-fuzz set up to the oss-fuzz folder.
    let cmdToExec = 'cp';
    let args: Array<string> = [
      '-rfT',
      workspaceFolder[0].uri.path + '/OSS-Fuzz/' + ossFuzzProjectName,
      extensionConfig.ossFuzzPepositoryWorkPath +
        '/projects/' +
        ossFuzzProjectName +
        '/',
    ];

    if (!(await systemSyncLogIfFailure(cmdToExec, args))) {
      println('Failed to copy project');
      return false;
    }

    // Build the fuzzers using OSS-Fuzz infrastructure.
    cmdToExec = 'python3';
    args = [
      extensionConfig.ossFuzzPepositoryWorkPath + '/infra/helper.py',
      'build_fuzzers',
    ];
    println('DECIDING ABOUT SANITIZER');
    if (sanitizer !== '') {
      println('ADDING CODE COVERAGE SANITIZER');
      args.push('--sanitizer=' + sanitizer);
    }

    if (toClean) {
      args.push('--clean');
    }

    args.push(ossFuzzProjectName);
    println('Building fuzzers');
    if (!(await systemSyncLogIfFailure(cmdToExec, args))) {
      println('Failed to build fuzzers');
      return false;
    }
  } else {
    ossFuzzProjectName = projectNameArg;

    const targetOssFuzzProject = vscode.Uri.file(
      extensionConfig.ossFuzzPepositoryWorkPath +
        '/projects/' +
        ossFuzzProjectName
    );
    // Check if the folder exists.
    let projectHasOssFuzzFolder = false;
    try {
      await vscode.workspace.fs.readDirectory(targetOssFuzzProject);
      projectHasOssFuzzFolder = true;
    } catch {
      projectHasOssFuzzFolder = false;
    }

    /**
     * The workspace does not have a OSS-Fuzz specific folder but has
     * a folder in the OSS-Fuzz/projects/* directory. As such, we build
     * the project using that build.sh set up, but, instead of cloning
     * the repository we mount the workspace root onto what would normally
     * be cloned.
     */
    if (projectHasOssFuzzFolder) {
      // println('Found a target directory');

      // Build the fuzzers using OSS-Fuzz infrastructure.
      // First, Set up a temporary workpath that will be cleanup after
      const wsPath = workspaceFolder[0].uri.fsPath; // gets the path of the first workspace folder
      const cmdToExec2 = 'cp';
      const temporaryProjectPath =
        extensionConfig.ossFuzzPepositoryWorkPath +
        '/projects/' +
        ossFuzzProjectName +
        '/temporary-project';

      const args2: Array<string> = [
        '-rfT',
        wsPath.toString(),
        temporaryProjectPath,
      ];

      if (!(await systemSyncLogIfFailure(cmdToExec2, args2))) {
        println('Failed to build fuzzers');
        return false;
      }

      //const wsPath = workspaceFolder[0].uri.fsPath; // gets the path of the first workspace folder
      const temporaryDockerPath =
        extensionConfig.ossFuzzPepositoryWorkPath +
        '/projects/' +
        ossFuzzProjectName +
        '/Dockerfile';
      const temporaryDockerPath2 =
        extensionConfig.ossFuzzPepositoryWorkPath +
        '/projects/' +
        ossFuzzProjectName +
        '/Dockerfile2';

      const args3: Array<string> = [temporaryDockerPath, temporaryDockerPath2];
      if (!(await systemSyncLogIfFailure('cp', args3))) {
        println('Failed to copy Dockerfile');
        return false;
      }

      // Append COPY command to Dockerfile
      fs.appendFileSync(
        temporaryDockerPath,
        'COPY temporary-project /src/' + ossFuzzProjectName
      );

      // Second, build the actual fuzzers using the temporarily created project path for mount.
      const cmdToExec = 'python3';
      const args = [
        extensionConfig.ossFuzzPepositoryWorkPath + '/infra/helper.py',
        'build_fuzzers', // command
      ];

      // Add sanitizer if needed.
      if (sanitizer !== '') {
        args.push('--sanitizer=' + sanitizer);
      }

      // Add clean flag if needed.
      if (toClean) {
        args.push('--clean');
      }

      args.push(ossFuzzProjectName);
      /*
      Previously we used OSS-Fuzz logic that supports mounting paths for getting
      the workspace into the Dockerfile.
      This approach, however, has limitations in that most builds will modify
      the contents of the folder they're working in. This can cause issues and also
      make it not possible to build several versions of the project with changing
      sanitizers in a sequence. As such, we disbanded.
      */
      println('Building fuzzers');
      if (!(await systemSyncLogIfFailure(cmdToExec, args))) {
        println('Failed to copy Dockerfile');
        // Move back the modified Dockerfile
        const args5: Array<string> = [
          temporaryDockerPath2,
          temporaryDockerPath,
        ];
        if (!(await systemSyncLogIfFailure('mv', args5))) {
          println('Failed to copy back Dockerfile');
          return false;
        }
        return false;
      }

      // Move back the modified Dockerfile
      const args5: Array<string> = [temporaryDockerPath2, temporaryDockerPath];
      if (!(await systemSyncLogIfFailure('mv', args5))) {
        println('Failed to copy back Dockerfile');
        return false;
      }
    } else {
      println('OSS-Fuzz does not have the relevant project folder');
      return false;
    }
  }

  // If we go to here we successfully build the project. Give information.
  vscode.window.showInformationMessage('Successfully build project');

  // List the fuzzers build
  await listFuzzersForProject(
    ossFuzzProjectName,
    extensionConfig.ossFuzzPepositoryWorkPath
  );
  return true;
}

/**
 * Runs the fuzzer for a given project.
 */
export async function runFuzzerHandler(
  projectNameArg: string,
  fuzzerNameArg: string,
  secondsToRunArg: string,
  fuzzerCorpusPath: string
) {
  // Check there is a valid OSS-Fuzz path. If not, bail out.
  if (
    (await isPathValidOssFuzzPath(
      extensionConfig.ossFuzzPepositoryWorkPath
    )) === false
  ) {
    println('Missing valid OSS-Fuzz path.');
    return;
  }
  // The fuzzer is run by way of OSS-Fuzz's helper.py so we use python3 to launch
  // this script.
  const cmdToExec = 'python3';

  // Set the arguments correctly. The ordering here is important for compatibility
  // with the underlying argparse used by OSS-Fuzz helper.py.
  const args: Array<string> = [
    extensionConfig.ossFuzzPepositoryWorkPath + '/infra/helper.py',
    'run_fuzzer',
  ];
  if (fuzzerCorpusPath !== '') {
    args.push('--corpus-dir');
    args.push(fuzzerCorpusPath);
  }
  args.push(projectNameArg);
  args.push(fuzzerNameArg);
  args.push('--');
  args.push('-max_total_time=' + secondsToRunArg);

  println(
    'Running fuzzer' +
      fuzzerNameArg +
      ' from project ' +
      projectNameArg +
      ' for ' +
      secondsToRunArg +
      ' seconds.'
  );

  // Run the actual command
  if (!(await systemSyncLogIfFailure(cmdToExec, args))) {
    println('Failed to run fuzzer');
    return false;
  }
  return true;
}

// Validates if a directory is a valid oss-fuzz path.
export async function isPathValidOssFuzzPath(path: string) {
  try {
    if (await vscode.workspace.fs.readDirectory(vscode.Uri.file(path))) {
      // println('Is a directory');
      // const helperPath = vscode.Uri.file(path + '/infra/helper.py');
      const helperPath = path + '/infra/helper.py';
      //console.log('Checking ' + helperPath.toString());
      if (fs.existsSync(helperPath.toString())) {
        return true;
      }
    }
  } catch {
    /* empty */
  }
  return false;
}
