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

import * as vscode from "vscode";

var child_process = require("child_process");

// Global configurations
// Root folder of the OSS-Fuzz repository
var oss_fuzz_repository_path = "/tmp/oss-fuzz";

// Map of projects to local file paths. This is used to make it easy to
// point a folder to a local directory that will be used when building
// the project in OSS-Fuzz.
let project_to_local_paths = new Map<string, string>();

// Helper method to execute commands on the system.
function systemSync(cmd: string) {
  try {
    let res = child_process.execSync(cmd);
    return [ true, res.toString() ];
  } catch (error: any) {
    let err_msg = (
      error.status +
      "====" +
      error.stdout +
      "======" +
      error.stderr +
      "======" +
      error.message
    )
    return [ false, err_msg];
  }
}

// Validates if a directory is a valid oss-fuzz path.
async function is_valid_oss_fuzz_path(path: string) {
  let is_valid = false;
  try {
    if (await vscode.workspace.fs.readDirectory(vscode.Uri.file(path))) {
      console.log("Is a directory");
      let helper_path = vscode.Uri.file(path + "/infra/helper.py");
      if (await vscode.workspace.fs.readFile(helper_path)) {
        // Found helper file
        is_valid = true;
      }
      is_valid = true;
    } else {
      //console.log("Not a directory");
      is_valid = false;
    }
  } catch {
    //console.log("Failed to check directory");
    is_valid = false;
  }
  return is_valid;
}

// Builds fuzzers for a given project.
async function build_fuzzers_handler() {
  let has_valid_ossfuzz_path = await is_valid_oss_fuzz_path(oss_fuzz_repository_path);
  if (has_valid_ossfuzz_path == false) {
    console.log("Missing valid OSS-Fuzz path.");
    return;
  }

  const projectName = await vscode.window.showInputBox({
    value: "",
    placeHolder: "Type a project name",
  });

  if (!projectName) {
    return;
  }
  const execSync = require("child_process").execSync;

  // Start assembling the command.
  let cmdToExec =
    "python3 " +
    oss_fuzz_repository_path +
    "/infra/helper.py build_fuzzers " +
    projectName;

  // Set local path to use if set.
  if (project_to_local_paths.has(projectName)) {
    console.log("Has value");
    let localPath = project_to_local_paths.get(projectName);
    cmdToExec += " " + localPath;
  }

  // Run the command
  console.log("Building fuzzers for " + projectName);
  const [res, cmd_msg] = systemSync(cmdToExec);
  if (res == false) {
    console.log("Failed to build project");
    console.log(cmd_msg);
  }

  console.log("Output was:\n", cmd_msg);
  vscode.window.showInformationMessage(projectName);
  vscode.window.showInformationMessage(cmd_msg);
}

// Function for setting up oss-fuzz. This clones the relevant directory
// and sets the oss-fuzz variable accordingly.
async function setup_ossfuzz_handler() {
  console.log("Setting up oss-fuzz in /tmp/");

  // First check if we already have an OSS-Fuzz path
  let tmp_oss_fuzz_repository_path = "/tmp/oss-fuzz";
  let has_valid_ossfuzz_path = await is_valid_oss_fuzz_path(tmp_oss_fuzz_repository_path);
  if (has_valid_ossfuzz_path == true) {
    console.log("OSS-Fuzz already exists in /tmp/oss-fuzz");
	oss_fuzz_repository_path = tmp_oss_fuzz_repository_path;
    return;
  }

  let cmdToExec = "git clone https://github.com/google/oss-fuzz " + tmp_oss_fuzz_repository_path;
  console.log("Command to exec: " + cmdToExec);
  const [res, output] = systemSync(cmdToExec);
  if (res == false) {
    console.log("Failed to run fuzzer");
    console.log(output);
  }
  console.log("Finished cloning oss-fuzz");

  oss_fuzz_repository_path = tmp_oss_fuzz_repository_path;
}

// Runs the fuzzer for a given project.
async function run_fuzzer_handler() {
  // Get the OSS-Fuzz path
  let has_valid_ossfuzz_path = await is_valid_oss_fuzz_path(oss_fuzz_repository_path);
  if (has_valid_ossfuzz_path == false) {
    console.log("Missing valid OSS-Fuzz path.");
    return;
  }
  let cmdToExec = "python3 " + oss_fuzz_repository_path + "/infra/helper.py run_fuzzer ";
  // Runs a fuzzer from a given project.
  const projectName = await vscode.window.showInputBox({
    value: "",
    placeHolder: "Type a project name",
  });
  if (!projectName) {
    console.log("Failed to get project name");
    return;
  }
  cmdToExec += projectName;

  // Get fuzzer name
  const fuzzerName = await vscode.window.showInputBox({
    value: "",
    placeHolder: "Type a fuzzer name",
  });
  if (!fuzzerName) {
    console.log("Failed to get fuzzer name");
    return;
  }
  cmdToExec += " " + fuzzerName;

  // Get the amount of seconds to run
  const secondsToRun = await vscode.window.showInputBox({
    value: "",
    placeHolder: "Type the number of seconds to run the fuzzer",
  });
  if (!secondsToRun) {
    return;
  }
  cmdToExec += " -- --max_total_time=" + secondsToRun;

  console.log(
    "Running fuzzer" +
      fuzzerName +
      " from project " +
      projectName +
      " for " +
      secondsToRun +
      " seconds."
  );
  console.log("Command to run: " + cmdToExec);

  const [res, output] = systemSync(cmdToExec);
  if (res == false) {
    console.log("Failed to run fuzzer");
  }

  console.log("Output was:\n", output);
  vscode.window.showInformationMessage(projectName);
  vscode.window.showInformationMessage(output);
}

// Lists all the fuzzers for a project.
async function list_fuzzers_handler() {
  // Lists all of the fuzzers from a project.
  const projectName = await vscode.window.showInputBox({
    value: "",
    placeHolder: "Type a project name",
  });
  console.log("Listing fuzzers for project " + projectName);
}

// Check if the the fuzzers passes check_build.
async function check_build_handler() {
  // Checks if a project builds successfully.
  console.log("Checking project is build");
}

// Get path of OSS-Fuzz
async function get_oss_fuzz_path() {
  console.log(oss_fuzz_repository_path);
}

// Set the path of the OSS-Fuzz directory based on user input.
async function set_project_path() {
  console.log("Setting project path");
  const projectName = await vscode.window.showInputBox({
    value: "",
    placeHolder: "The project to set path for.",
  });
  if (!projectName) {
    return;
  }
  const projectPath = await vscode.window.showInputBox({
    value: "",
    placeHolder: "The path for the given project.",
  });
  if (!projectPath) {
    return;
  }
  var key: string = projectName;
  project_to_local_paths.set(key, projectPath);
}

// Return the local path of a project. If a project has a local path this corresponds
// to the path that will be used for source when building fuzzers.
async function get_project_path() {
  const projectName = await vscode.window.showInputBox({
    value: "",
    placeHolder: "The project to set path for.",
  });
  if (!projectName) {
    return;
  }
  if (project_to_local_paths.has(projectName)) {
    console.log("Has value");
  } else {
    console.log("Does not have vlue");
  }
}

// Set the oss-fuzz path.
async function set_oss_fuzz_path() {
  console.log("Setting path");
  const new_oss_fuzz_path = await vscode.window.showInputBox({
    value: "",
    placeHolder: "Type path",
  });
  if (!new_oss_fuzz_path) {
    console.log("Failed getting path");
    return;
  }

  let fpathh = vscode.Uri.file(new_oss_fuzz_path);
  let is_valid = false;
  try {
    if (await vscode.workspace.fs.readDirectory(fpathh)) {
      console.log("Is a directory");
      let helper_path = vscode.Uri.file(new_oss_fuzz_path + "/infra/helper.py");
      if (await vscode.workspace.fs.readFile(helper_path)) {
        console.log("Found helper file");
        is_valid = true;
      }
      is_valid = true;
    } else {
      is_valid = false;
    }
  } catch {
    is_valid = false;
  }

  if (is_valid) {
    oss_fuzz_repository_path = new_oss_fuzz_path;
  } else {
    console.log("Not setting OSS-Fuzz path");
  }
}

// Runs introspector on a given project.
async function run_introspector() {
  console.log("Running introspector");

  // Get the OSS-Fuzz path
  let has_valid_ossfuzz_path = await is_valid_oss_fuzz_path(oss_fuzz_repository_path);
  if (has_valid_ossfuzz_path == false) {
    console.log("Missing valid OSS-Fuzz path.");
    return;
  }
  let cmdToExec = "python3 " + oss_fuzz_repository_path + "/infra/helper.py introspector ";
  const projectName = await vscode.window.showInputBox({
    value: "",
    placeHolder: "Type a project name",
  });
  if (!projectName) {
    console.log("Failed to get project name");
    return;
  }
  cmdToExec += projectName;

  // Get the amount of seconds to run.
  const secondsToRun = await vscode.window.showInputBox({
    value: "",
    placeHolder: "Type the number of seconds to run the fuzzer",
  });
  if (!secondsToRun) {
    return;
  }
  cmdToExec += " --seconds=" + secondsToRun;
  console.log("Command to run: " + cmdToExec);

  const [res, output] = systemSync(cmdToExec);
  if (res == false) {
    console.log("Failed to run introspector");
  }

  console.log("Output was:\n", output);
  vscode.window.showInformationMessage(projectName);
  vscode.window.showInformationMessage(output);  
}

// This method is called when your extension is activated
// Your extension is activated the very first time the command is executed
export function activate(context: vscode.ExtensionContext) {
  console.log('OSS-Fuzz extension is now active!');

  // Command registration
  let disposable2 = vscode.commands.registerCommand(
    "oss-fuzz.buildFuzzers",
    build_fuzzers_handler
  );
  context.subscriptions.push(disposable2);
  let disposable3 = vscode.commands.registerCommand(
    "oss-fuzz.SetUpOssFuzz",
    setup_ossfuzz_handler
  );
  context.subscriptions.push(disposable3);
  let disposable4 = vscode.commands.registerCommand(
    "oss-fuzz.RunFuzzer",
    run_fuzzer_handler
  );
  context.subscriptions.push(disposable4);
  let disposable5 = vscode.commands.registerCommand(
    "oss-fuzz.ListFuzzers",
    list_fuzzers_handler
  );
  context.subscriptions.push(disposable5);
  let disposable6 = vscode.commands.registerCommand(
    "oss-fuzz.SetOSSFuzzPath",
    set_oss_fuzz_path
  );
  context.subscriptions.push(disposable6);
  let disposable7 = vscode.commands.registerCommand(
    "oss-fuzz.GetOSSFuzzPath",
    get_oss_fuzz_path
  );
  context.subscriptions.push(disposable7);
  let disposable8 = vscode.commands.registerCommand(
    "oss-fuzz.SetProjectPath",
    set_project_path
  );
  context.subscriptions.push(disposable8);
  let disposable9 = vscode.commands.registerCommand(
    "oss-fuzz.GetProjectPath",
    get_project_path
  );
  context.subscriptions.push(disposable9);
  let disposable10 = vscode.commands.registerCommand(
    "oss-fuzz.checkBuild",
    check_build_handler
  );
  context.subscriptions.push(disposable10);

  let disposable11 = vscode.commands.registerCommand(
    "oss-fuzz.RunIntrospector",
    run_introspector
  );
  context.subscriptions.push(disposable11);  
}

// This method is called when your extension is deactivated
export function deactivate() {
  console.log("Deactivating the extension");
}
