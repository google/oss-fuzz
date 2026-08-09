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

import {println} from '../logger';
import {extensionConfig} from '../config';

// Set the oss-fuzz path.
export async function setOssFuzzPath() {
  println('Setting path');
  const newOssFuzzPath = await vscode.window.showInputBox({
    value: '',
    placeHolder: 'Type path',
  });
  if (!newOssFuzzPath) {
    println('Failed getting path');
    return;
  }

  const fpathh = vscode.Uri.file(newOssFuzzPath);
  let isValid = false;
  try {
    if (await vscode.workspace.fs.readDirectory(fpathh)) {
      println('Is a directory');
      const helperPathURI = vscode.Uri.file(
        newOssFuzzPath + '/infra/helper.py'
      );
      if (await vscode.workspace.fs.readFile(helperPathURI)) {
        println('Found helper file');
        isValid = true;
      }
      isValid = true;
    } else {
      isValid = false;
    }
  } catch {
    isValid = false;
  }

  if (isValid) {
    extensionConfig.ossFuzzPepositoryWorkPath = newOssFuzzPath;
  } else {
    println('Not setting OSS-Fuzz path');
  }
}
