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
import {Uri} from 'vscode';
import {println} from './logger';
import {getApi, FileDownloader} from '@microsoft/vscode-file-downloader-api';
import {extensionConfig} from './config';

const path = require('path');
let isCodeCoverageEnabled = false;

// create a decorator type that we use to decorate small numbers
const codeCoveredLineDecorationType =
  vscode.window.createTextEditorDecorationType({
    backgroundColor: '#184916',
    overviewRulerColor: 'blue',
    overviewRulerLane: vscode.OverviewRulerLane.Right,
    light: {
      // this color will be used in light color themes
      borderColor: 'darkblue',
    },
    dark: {
      // this color will be used in dark color themes
      borderColor: 'lightblue',
    },
  });

const missingLineDecorationType = vscode.window.createTextEditorDecorationType({
  backgroundColor: '#6C2B34',
  overviewRulerColor: 'blue',
  overviewRulerLane: vscode.OverviewRulerLane.Right,
  light: {
    // this color will be used in light color themes
    borderColor: 'darkblue',
  },
  dark: {
    // this color will be used in dark color themes
    borderColor: 'lightblue',
  },
});

export async function loadSummaryJsonCoverage(
  context: vscode.ExtensionContext,
  codeCoverageFile: Uri
) {
  const coverageSummaryRawJson = await vscode.workspace.openTextDocument(codeCoverageFile);
  const jsonCodeCoverage = JSON.parse(coverageSummaryRawJson.getText());
  return jsonCodeCoverage;
}

export async function compareLocalToRemoteCoverage(
  context: vscode.ExtensionContext,
  projectName: string
){
  println("Checking the file matching");
  /* Get the coverage from the remote server */
  const fileDownloader: FileDownloader = await getApi();

  const currentDate = new Date();
  const yesterday = new Date(currentDate);
  yesterday.setDate(yesterday.getDate() - 1);

  const day = yesterday.getDate();
  const month = yesterday.getMonth();
  const year = yesterday.getFullYear();

  var urlString = 'https://storage.googleapis.com/oss-fuzz-coverage/' +
  projectName +
  '/reports/' +
  year.toString();

  if (month < 10) {
    urlString += "0";
  }
  urlString += month.toString();
  if (day < 10) {
    urlString += "0";
  }
  urlString += day.toString();
  urlString += '/linux/summary.json';

  println("URL: " + urlString);
  var codeCoverageFile: vscode.Uri;
  try {
    codeCoverageFile = await fileDownloader.downloadFile(
      vscode.Uri.parse(
        urlString
      ),
      'summary.json',
      context
    );

  } catch (err) {
    println(
      'Could not get the URL. Currently, this feature is only supported for Python projects'
    );
    return;
  }
  const remoteCoverage = await loadSummaryJsonCoverage(context, codeCoverageFile);

  /* Get the local coverage report */
  // Compare the local coverage to the upstream coverage
  const summaryCovPath =
    extensionConfig.ossFuzzPepositoryWorkPath +
    '/build/out/' +
    projectName +
    '/report/linux/summary.json';
  const localCodeCoverage = await loadSummaryJsonCoverage(context, vscode.Uri.file(summaryCovPath));

  for (var i = 0; i < localCodeCoverage.data[0].files.length; i++) {
    for (var j = 0; j < remoteCoverage.data[0].files.length; j++) {
      if (localCodeCoverage.data[0].files[i].filename == remoteCoverage.data[0].files[j].filename) {
        const remoteFuncCount = remoteCoverage.data[0].files[j].summary.functions.count;
        const localFuncCount = localCodeCoverage.data[0].files[i].summary.functions.count;

        if (localFuncCount > remoteFuncCount) {
          println("Coverage improved in :" +
            localCodeCoverage.data[0].files[i].filename +
            " [" + localFuncCount + " : " + remoteFuncCount + "]");
        }
      }
    }
  }
}

/**
 *
 * @param context Adds visualisation to the editor based on reading a code coverage file.
 * @param codeCoverageFile
 */
export async function loadCoverageIntoWorkspace(
  context: vscode.ExtensionContext,
  codeCoverageFile: Uri
) {
  isCodeCoverageEnabled = true;

  const doc3 = await vscode.workspace.openTextDocument(codeCoverageFile);
  const jsonCodeCoverageObj3 = JSON.parse(doc3.getText());

  const codeCoverageMappingWithCoverage = new Map();
  const codeCoverageMapMissingCoverage = new Map();

  Object.entries(jsonCodeCoverageObj3['files']).forEach(entry => {
    const [key, value] = entry;
    println(key);
    const filename = path.parse(key).base;
    println('Filename base: ' + filename);
    const objectDictionary: any = value as any;
    const linesWithCodeCoverage: unknown[] = [];
    println(objectDictionary['executed_lines']);
    Object.entries(objectDictionary['executed_lines']).forEach(entryInner => {
      const lineNumber = entryInner[1];
      //println("executed line: " + lineNumber);
      linesWithCodeCoverage.push(lineNumber);
    });
    codeCoverageMappingWithCoverage.set(filename, linesWithCodeCoverage);

    const linesMissingCodeCoverage: unknown[] = [];
    Object.entries(objectDictionary['missing_lines']).forEach(entryInner => {
      const lineNumber = entryInner[1];
      //println("executed line: " + line_numb);
      linesMissingCodeCoverage.push(lineNumber);
    });
    codeCoverageMapMissingCoverage.set(filename, linesMissingCodeCoverage);
  });
  println('=========>');

  println('Enabling code coverage decorator');
  println('decorator sample is activated');

  let timeout: NodeJS.Timer | undefined = undefined;

  // create a decorator type that we use to decorate large numbers

  let activeEditor = vscode.window.activeTextEditor;

  function updateDecorations(
    linesWithCodeCoverage: any,
    linesWithoNoCodeCoverage: any
  ) {
    if (!isCodeCoverageEnabled) {
      return;
    }
    if (!activeEditor) {
      return;
    }
    println('Filename');
    println(activeEditor.document.fileName);

    // Current file opened in the editor.
    const nameOfCurrentFile = path.parse(activeEditor.document.fileName).base;

    println('Base filename: ' + nameOfCurrentFile);
    println('Done filename');
    const lineNumbersWithCoverage: vscode.DecorationOptions[] = [];
    const missingLineNumbers: vscode.DecorationOptions[] = [];

    if (linesWithCodeCoverage.has(nameOfCurrentFile)) {
      println('Has this file');
      const elemWithCov = linesWithCodeCoverage.get(nameOfCurrentFile);
      for (let idx = 0; idx < elemWithCov.length; idx++) {
        const lineNo = elemWithCov[idx];
        println('Setting up: ' + lineNo);
        lineNumbersWithCoverage.push({
          range: new vscode.Range(lineNo - 1, 0, lineNo, 0),
        });
      }

      const elemNoCov = linesWithoNoCodeCoverage.get(nameOfCurrentFile);
      for (let idx = 0; idx < elemNoCov.length; idx++) {
        const lineNo = elemNoCov[idx];
        println('Setting up: ' + lineNo);
        missingLineNumbers.push({
          range: new vscode.Range(lineNo - 1, 0, lineNo, 0),
        });
      }
    } else {
      println('Does not have this file');
    }

    activeEditor.setDecorations(
      codeCoveredLineDecorationType,
      lineNumbersWithCoverage
    );
    activeEditor.setDecorations(missingLineDecorationType, missingLineNumbers);
    //activeEditor.setDecorations(largeNumberDecorationType, largeNumbers);
  }

  function triggerUpdateDecorations(
    throttle = false,
    covMap: any,
    covMisMap: any
  ) {
    if (timeout) {
      clearTimeout(timeout);
      timeout = undefined;
    }
    if (throttle) {
      //timeout = setTimeout(updateDecorations, 500);
      updateDecorations(covMap, covMisMap);
    } else {
      updateDecorations(covMap, covMisMap);
    }
  }

  if (activeEditor) {
    triggerUpdateDecorations(
      false,
      codeCoverageMappingWithCoverage,
      codeCoverageMapMissingCoverage
    );
  }

  vscode.window.onDidChangeActiveTextEditor(
    editor => {
      activeEditor = editor;
      if (editor) {
        triggerUpdateDecorations(
          false,
          codeCoverageMappingWithCoverage,
          codeCoverageMapMissingCoverage
        );
      }
    },
    null,
    context.subscriptions
  );

  vscode.workspace.onDidChangeTextDocument(
    event => {
      if (activeEditor && event.document === activeEditor.document) {
        triggerUpdateDecorations(
          true,
          codeCoverageMappingWithCoverage,
          codeCoverageMapMissingCoverage
        );
      }
    },
    null,
    context.subscriptions
  );
}

/**
 * Removes the values from the mappings used to track code coverage. As a
 * result, the visualisation disappears.
 */
export async function clearCoverage() {
  // Set global indicator.
  const activeEditor = vscode.window.activeTextEditor;
  isCodeCoverageEnabled = false;
  if (activeEditor) {
    activeEditor.setDecorations(codeCoveredLineDecorationType, []);
    activeEditor.setDecorations(missingLineDecorationType, []);
  }
}
