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
import {loadCoverageIntoWorkspace} from '../coverageHelper';
import {println} from '../logger';
import {getApi, FileDownloader} from '@microsoft/vscode-file-downloader-api';

/*
 * Displays code coverage from OSS-Fuzz.
 *
 * Downloads a code coverage report from the OSS-Fuzz online storage, and then overlays
 * the relevant source files with the coverage information.
 */
export async function displayCodeCoverageFromOssFuzz(
  context: vscode.ExtensionContext
) {
  const projectName = await vscode.window.showInputBox({
    value: '',
    placeHolder: "The project you'd like to get code coverage for.",
  });
  if (!projectName) {
    return;
  }
  println('Getting code coverage for ' + projectName);

  const fileDownloader: FileDownloader = await getApi();

  const currentDate = new Date();
  const yesterday = new Date(currentDate);
  yesterday.setDate(yesterday.getDate() - 1);

  const day = yesterday.getDate();
  const month = yesterday.getMonth();
  const year = yesterday.getFullYear();

  try {
    const codeCoverageFile: vscode.Uri = await fileDownloader.downloadFile(
      vscode.Uri.parse(
        'https://storage.googleapis.com/oss-fuzz-coverage/' +
          projectName +
          '/textcov_reports/' +
          year.toString() +
          month.toString() +
          day.toString() +
          '/all_cov.json'
      ),
      'all_cov.json',
      context
    );
    await loadCoverageIntoWorkspace(context, codeCoverageFile);
  } catch (err) {
    println(
      'Could not get the URL. Currently, this feature is only supported for Python projects'
    );
    return;
  }
}
