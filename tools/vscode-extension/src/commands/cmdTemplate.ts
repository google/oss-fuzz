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

/**
 * Command for generating template fuzzers. This is a short-cut for rapid
 * prototyping as well as an archive for inspiration.
 */
import * as vscode from 'vscode';
import {println} from '../logger';

const cLangSimpleStringFuzzer = `#include <stdint.h>
#include <string.h>
#include <stdlib.h>

int 
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char *new_str = (char *)malloc(size+1);
    if (new_str == NULL){
        return 0;
    }
    memcpy(new_str, data, size);
    new_str[size] = '\\0';

    // Insert fuzzer contents here 
    // fuzz data in new_str

    // end of fuzzer contents

    free(new_str);
    return 0;
}`;

const cLangFileInputFuzzer = `int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char filename[256];
	sprintf(filename, "/tmp/libfuzzer.%d", getpid());

  // Create a file on the filesystem with fuzzer data in it
	FILE *fp = fopen(filename, "wb");
	if (!fp) {
		return 0;
  }
	fwrite(data, size, 1, fp);
	fclose(fp);

	// Fuzzer logic here. Use the file as a source of data.

	// Fuzzer logic end

  // Clean up the file.
	unlink(filename);

	return 0;
}`;

const cLangBareTemplateFuzzer = `int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	return 0;
}`;

const cppLangBareTemplateFuzzer = `extern "C" int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	return 0;
}`;

const cppLangStdStringTemplateFuzzer = `extern "C" int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  std::string input(reinterpret_cast<const char*>(data), size);

  return 0;
}`;

const cppLangFDPTemplateFuzzer = `#include <fuzzer/FuzzedDataProvider.h>

#include <string>

extern "C" int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  FuzzedDataProvider fdp(data, size);

  // Extract higher level data types used for fuzzing, e.g.
  // int ran_int = fdp.ConsumeIntegralInRange<int>(1, 1024);
  // std::string s = fdp.ConsumeRandomLengthString();

  return 0;
}`;

const cppLangFileInputFuzzer = `extern "C" int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char filename[256];
	sprintf(filename, "/tmp/libfuzzer.%d", getpid());

	FILE *fp = fopen(filename, "wb");
	if (!fp) {
		return 0;
  }
	fwrite(data, size, 1, fp);
	fclose(fp);

	// Fuzzer logic here

	// Fuzzer logic end

	unlink(filename);
}`;

const pythonLangBareTemplate = `import sys
import atheris


def TestOneInput(fuzz_bytes):
    return


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()`;

const pythonLangFileInputFuzzer = `import sys
import atheris

@atheris.instrument_func
def TestOneInput(data):
  # Write fuzz data to a file
  with open('/tmp/fuzz_input.b') as f:
    f.write(data)
  
  # Use '/tmp/fuzz_input.b' as input to file handling logic.

  
def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()


if __name__ == "__main__":
  main()`;

const pythonLongFdpTemplate = `import sys
import atheris

def TestOneInput(fuzz_bytes):
    fdp = atheris.FuzzedDataProvider(fuzz_bytes)
    return

def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()

if __name__ == "__main__":
    main()`;

const javaLangBareTemplate = `import com.code_intelligence.jazzer.api.FuzzedDataProvider;
public class SampleFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider fdp) {
    // Use fdp to create arbitrary types seeded with fuzz data
  }
}
`;

/**
 * C templates
 */
async function cTemplates() {
  let template = '';
  const result = await vscode.window.showQuickPick(
    ['Bare template', 'Null-terminated string input', 'File input'],
    {
      placeHolder: 'Pick which template',
    }
  );
  vscode.window.showInformationMessage(`Got: ${result}`);

  if (result === 'Null-terminated string input') {
    template = cLangSimpleStringFuzzer;
  } else if (result === 'File input') {
    template = cLangFileInputFuzzer;
  } else if (result === 'Bare template') {
    template = cLangBareTemplateFuzzer;
  } else {
    template = 'empty';
  }
  const workspaceFolder = vscode.workspace.workspaceFolders;
  if (!workspaceFolder) {
    return;
  }

  const wsPath = workspaceFolder[0].uri.fsPath; // gets the path of the first workspace folder

  const cifuzzYml = vscode.Uri.file(wsPath + '/oss-fuzz-template.c');
  const wsedit = new vscode.WorkspaceEdit();
  wsedit.createFile(cifuzzYml, {ignoreIfExists: true});
  wsedit.insert(cifuzzYml, new vscode.Position(0, 0), template);
  vscode.workspace.applyEdit(wsedit);
  return;
}

/**
 * CPP templates
 */
async function cppTemplates() {
  let template = '';
  const result = await vscode.window.showQuickPick(
    [
      'Bare template',
      'Simple CPP string',
      'File input fuzzer',
      'Fuzzed data provider',
    ],
    {
      placeHolder: 'Pick which template',
    }
  );
  vscode.window.showInformationMessage(`Got: ${result}`);

  if (result === 'Bare template') {
    template = cppLangBareTemplateFuzzer;
  } else if (result === 'Simple CPP string') {
    template = cppLangStdStringTemplateFuzzer;
  } else if (result === 'File input fuzzer') {
    template = cppLangFileInputFuzzer;
  } else if (result === 'Fuzzed data provider') {
    template = cppLangFDPTemplateFuzzer;
  } else {
    template = 'empty';
  }
  const workspaceFolder = vscode.workspace.workspaceFolders;
  if (!workspaceFolder) {
    return;
  }

  const wsPath = workspaceFolder[0].uri.fsPath; // gets the path of the first workspace folder

  const cifuzzYml = vscode.Uri.file(wsPath + '/oss-fuzz-template.cpp');
  const wsedit = new vscode.WorkspaceEdit();
  wsedit.createFile(cifuzzYml, {ignoreIfExists: true});
  wsedit.insert(cifuzzYml, new vscode.Position(0, 0), template);
  vscode.workspace.applyEdit(wsedit);
  return;
}

/**
 * Python templates
 */
async function pythonTepmlates() {
  let template = '';
  const result = await vscode.window.showQuickPick(
    ['Bare template', 'Fuzzed Data Provider', 'File input fuzzer'],
    {
      placeHolder: 'Pick which template',
    }
  );
  vscode.window.showInformationMessage(`Got: ${result}`);

  if (result === 'Fuzzed Data Provider') {
    template = pythonLongFdpTemplate;
  } else if (result === 'Bare template') {
    template = pythonLangBareTemplate;
  } else if (result === 'File input fuzzer') {
    template = pythonLangFileInputFuzzer;
  } else {
    template = 'empty';
  }
  const workspaceFolder = vscode.workspace.workspaceFolders;
  if (!workspaceFolder) {
    return;
  }

  const wsPath = workspaceFolder[0].uri.fsPath; // gets the path of the first workspace folder

  const cifuzzYml = vscode.Uri.file(wsPath + '/oss-fuzz-template.py');
  const wsedit = new vscode.WorkspaceEdit();
  wsedit.createFile(cifuzzYml, {ignoreIfExists: true});
  wsedit.insert(cifuzzYml, new vscode.Position(0, 0), template);
  vscode.workspace.applyEdit(wsedit);
  return;
}

/**
 * Java templates
 */
async function javaTemplates() {
  let template = '';
  const result = await vscode.window.showQuickPick(['Bare template'], {
    placeHolder: 'Pick which template',
  });
  vscode.window.showInformationMessage(`Got: ${result}`);

  if (result === 'Bare template') {
    template = javaLangBareTemplate;
  } else {
    template = 'empty';
  }
  const workspaceFolder = vscode.workspace.workspaceFolders;
  if (!workspaceFolder) {
    return;
  }

  const wsPath = workspaceFolder[0].uri.fsPath; // gets the path of the first workspace folder

  const cifuzzYml = vscode.Uri.file(wsPath + '/oss-fuzz-template.java');
  const wsedit = new vscode.WorkspaceEdit();
  wsedit.createFile(cifuzzYml, {ignoreIfExists: true});
  wsedit.insert(cifuzzYml, new vscode.Position(0, 0), template);
  vscode.workspace.applyEdit(wsedit);
  return;
}

export async function cmdDispatcherTemplate(context: vscode.ExtensionContext) {
  println('Creating template');
  const options: {
    [key: string]: (context: vscode.ExtensionContext) => Promise<void>;
  } = {
    C: cTemplates,
    CPP: cppTemplates,
    Python: pythonTepmlates,
    Java: javaTemplates,
  };

  const quickPick = vscode.window.createQuickPick();
  quickPick.items = Object.keys(options).map(label => ({label}));
  quickPick.onDidChangeSelection(selection => {
    if (selection[0]) {
      options[selection[0].label](context).catch(console.error);
    }
  });
  quickPick.onDidHide(() => quickPick.dispose());
  quickPick.placeholder = 'Pick language';
  quickPick.show();

  return;
}
