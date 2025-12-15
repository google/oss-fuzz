# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################
"""MCP server for OSS-Fuzz."""

import logging

import os
import shutil
import sys
import json
import time
import subprocess
from mcp.server.fastmcp import FastMCP

import config as oss_fuzz_mcp_config

TARGET_PROJECT = ''

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format=
    "[SERVER] %(asctime)s - %(name)s - '%(module)s - %(funcName)s - %(levelname)s - %(message)s",
    stream=sys.stderr)
logger = logging.getLogger("mcp-server")

# Create an MCP server with a name
mcp = FastMCP("OSS-Fuzz tools with relevant file system utilities.")

FILE_ACCESS_ERROR = f"""Error: Cannot access directories outside of the base directory.
Remember, all paths accessible by you must be prefixed with {oss_fuzz_mcp_config.BASE_DIR}.

Further:
1) For project source code, this is available within {oss_fuzz_mcp_config.BASE_PROJECTS_DIR}.
2) For access to OSS-Fuzz project files, these are accessible in {oss_fuzz_mcp_config.BASE_OSS_FUZZ_DIR}/projects/PROJECT_NAME/.
"""


def _internal_delay():
  """Forced delay to control LLM limits"""
  time.sleep(2)


def clone_oss_fuzz_if_it_does_not_exist():
  """Clones OSS-Fuzz if it does not already exist."""

  target = oss_fuzz_mcp_config.BASE_PROJECTS_DIR
  if os.path.isdir(target):
    logger.info('OSS-Fuzz already exists')
    return

  repo_url = "https://github.com/google/oss-fuzz"

  try:
    subprocess.check_call(["git", "clone", repo_url, target],
                          stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL,
                          cwd=oss_fuzz_mcp_config.BASE_DIR)

  except subprocess.CalledProcessError:
    logger.info('Error cloning OSS-Fuzz')


def _prepare_target_project():
  """Prepares the target OSS-Fuzz project by copying it to the OSS-Fuzz projects directory."""
  global TARGET_PROJECT

  clone_oss_fuzz_if_it_does_not_exist()
  project_name = os.path.basename(TARGET_PROJECT)
  # Copy over the project files if needed.
  if os.path.isdir(
      os.path.join(oss_fuzz_mcp_config.BASE_PROJECTS_DIR, 'projects',
                   project_name)):
    shutil.rmtree(
        os.path.join(oss_fuzz_mcp_config.BASE_PROJECTS_DIR, 'projects',
                     project_name))
  shutil.copytree(
      TARGET_PROJECT,
      os.path.join(oss_fuzz_mcp_config.BASE_PROJECTS_DIR, 'projects',
                   project_name))
  return project_name


@mcp.tool()
async def check_if_oss_fuzz_project_builds() -> bool:
  """
    Checks if the OSS-Fuzz project being worked on builds successfully.
    
    Returns:
        True if the project builds successfully, False otherwise
    """
  project_name = _prepare_target_project()

  logger.info("Checking if OSS-Fuzz project '%s' builds successfully...",
              project_name)

  try:
    logger.info('Building OSS-Fuzz project: %s', project_name)
    subprocess.check_call('python3 infra/helper.py build_fuzzers ' +
                          project_name,
                          cwd=oss_fuzz_mcp_config.BASE_OSS_FUZZ_DIR,
                          shell=True,
                          stdout=subprocess.DEVNULL,
                          stderr=subprocess.STDOUT,
                          timeout=60 * 20)
    return True
  except subprocess.CalledProcessError as e:
    logger.info("Build failed for project '%s': {%s}", project_name, str(e))
    return False
  except subprocess.TimeoutExpired:
    logger.info(f"Building project {project_name} timed out.")
  return False


def shorten_logs_if_needed(log_string: str) -> str:
  """
    Shortens the log string if it exceeds a certain length.
    
    Args:
        log_string: The log string to potentially shorten
    
    Returns:
        The original log string if it's short enough, or a shortened version
    """
  max_length = 5000  # Define a maximum length for logs
  if len(log_string) > max_length:
    return log_string[:1000] + '... [truncated] ' + log_string[-3700:]
  return log_string


@mcp.tool()
async def build_and_get_build_logs_from_oss_fuzz() -> str:
  """
    Retrieves build logs for an OSS-Fuzz project. This is useful when changes
    have been made to the project and you want to see the build output.
    
    Returns:
        A string containing the build logs for the project
    """
  project_name = _prepare_target_project()
  logger.info("Retrieving build logs for OSS-Fuzz project '%s'...",
              project_name)

  os.makedirs(oss_fuzz_mcp_config.BASE_TMP_LOGS, exist_ok=True)
  target_logs = os.path.join(oss_fuzz_mcp_config.BASE_TMP_LOGS, 'build-log.txt')
  if os.path.isfile(target_logs):
    os.remove(target_logs)

  log_stdout = open(target_logs, 'w', encoding='utf-8')

  try:
    logger.info("Building OSS-Fuzz project: '%s'", project_name)
    subprocess.check_call('python3 infra/helper.py build_fuzzers ' +
                          project_name,
                          cwd=oss_fuzz_mcp_config.BASE_OSS_FUZZ_DIR,
                          shell=True,
                          stdout=log_stdout,
                          stderr=subprocess.STDOUT,
                          timeout=60 * 20)
  except subprocess.CalledProcessError as e:
    logger.info("Build failed for project '%s': {%s}", project_name, str(e))
  except subprocess.TimeoutExpired:
    logger.info(f"Building project {project_name} timed out.")

  with open(target_logs, 'r', encoding='utf-8') as f:
    logs = f.read()
  logs_to_return = shorten_logs_if_needed(logs)
  logger.info("Build logs for project '%s': {%s}", project_name, logs_to_return)
  return logs_to_return


#@mcp.tool()
async def get_sample_artifacts_from_oss_fuzz_project(
    language: str) -> dict[str, str]:
  """
    Retrieves sample artifacts, Dockerfile and builds, for a specific language from OSS-Fuzz projects.
    
    Args:
        language: The programming language for which to retrieve sample artifacts

    Returns:
        A dictionary containing the Dockerfile and build script.
    """
  logger.info("Retrieving sample artifacts for OSS-Fuzz project language: %s",
              language)
  if language == 'go':
    project_name = 'go-dns'
  elif language == 'c':
    project_name = 'cjson'
  elif language == 'cpp':
    project_name = 'htslib'
  elif language == 'java':
    project_name = 'guava'
  else:
    return f"Error: Unsupported language '{language}'. Supported languages are: go, c, cpp, java."

  logger.info("Retrieving sample artifacts for OSS-Fuzz project '%s'...",
              project_name)

  dockerfile_path = os.path.join(oss_fuzz_mcp_config.BASE_PROJECTS_DIR,
                                 'projects', project_name, 'Dockerfile')
  build_script_path = os.path.join(oss_fuzz_mcp_config.BASE_PROJECTS_DIR,
                                   'projects', project_name, 'build.sh')
  if not os.path.isfile(dockerfile_path) or not os.path.isfile(
      build_script_path):
    return f"Error: Sample artifacts for project '{project_name}' not found."

  with open(dockerfile_path, 'r', encoding='utf-8') as f:
    dockerfile = f.read()
  with open(build_script_path, 'r', encoding='utf-8') as f:
    build_script = f.read()
  artifacts = {"Dockerfile": dockerfile, "build.sh": build_script}
  logger.info("Sample artifacts retrieved successfully for project '%s'.",
              project_name)
  return artifacts


#@mcp.tool()
async def check_run_tests(
    project_name) -> str:  #, build_sh, dockerfile) -> str:
  """
    OSS-Fuzz tool that performs "run-tests-check" on an OSS-Fuzz project.
    Use this tool to verify `run_tests.sh` scripts.
    Checks if an OSS-Fuzz project's tests run correctly.
    This check should only be applied after the project builds successfully.
    This check is needed for an OSS-Fuzz project to be in a good state.
    
    Args:
        project_name: Name of the OSS-Fuzz project to check
    
    Returns:
        The logs from building the project with custom artifacts.
    """
  clone_oss_fuzz_if_it_does_not_exist()
  logger.info(
      "Checking if OSS-Fuzz project '%s' builds with custom artifacts...",
      project_name)

  os.makedirs(oss_fuzz_mcp_config.BASE_TMP_LOGS, exist_ok=True)
  target_logs = os.path.join(oss_fuzz_mcp_config.BASE_TMP_LOGS,
                             'check-fuzz-run-tests-log.txt')
  if os.path.isfile(target_logs):
    os.remove(target_logs)
  log_stdout = open(target_logs, 'w', encoding='utf-8')
  try:
    subprocess.check_call(
        f'infra/experimental/chronos/check_tests.sh {project_name} c++',
        cwd=oss_fuzz_mcp_config.BASE_OSS_FUZZ_DIR,
        shell=True,
        stdout=log_stdout,
        stderr=subprocess.STDOUT,
        timeout=60 * 20)

  except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
    logger.info("Build failed for project '%s': {%s}", project_name, str(e))
    log_stdout.write("\n\nrun-tests.sh failed!!\n")
    with open(target_logs, 'r', encoding='utf-8') as f:
      logs = f.read()
    logs_to_return = shorten_logs_if_needed(logs)
    logger.info("run-tests.sh logs for project '%s': {%s}", project_name,
                logs_to_return)
    return logs_to_return

  with open(target_logs, 'r', encoding='utf-8') as f:
    logs = f.read()
  logs_to_return = shorten_logs_if_needed(logs)
  logger.info("run-tests.sh for project '%s': {%s}", project_name,
              logs_to_return)
  return logs_to_return


@mcp.tool()
async def check_oss_fuzz_fuzzers() -> str:
  """
    Performs "fuzzer-check" on an OSS-Fuzz project with custom artifacts.
    Checks if the OSS-Fuzz project's fuzzers run correctly with custom artifacts.
    This check should only be applied after the project builds successfully.
    This check is needed for an OSS-Fuzz project to be in a good state.
    
    Returns:
        The build logs from building the project with custom artifacts.
    """
  project_name = _prepare_target_project()
  logger.info(
      "Checking if OSS-Fuzz project '%s' builds and fuzzers pass check_build",
      project_name)

  os.makedirs(oss_fuzz_mcp_config.BASE_TMP_LOGS, exist_ok=True)
  target_logs = os.path.join(oss_fuzz_mcp_config.BASE_TMP_LOGS,
                             'check-fuzz-build-log.txt')
  if os.path.isfile(target_logs):
    os.remove(target_logs)
  log_stdout = open(target_logs, 'w', encoding='utf-8')
  try:
    subprocess.check_call('python3 infra/helper.py build_fuzzers ' +
                          project_name,
                          cwd=oss_fuzz_mcp_config.BASE_OSS_FUZZ_DIR,
                          shell=True,
                          stdout=log_stdout,
                          stderr=subprocess.STDOUT,
                          timeout=60 * 20)

  except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
    logger.info("Build failed for project '%s': {%s}", project_name, str(e))
    log_stdout.write("\n\nBuild failed!!\n")
    with open(target_logs, 'r', encoding='utf-8') as f:
      logs = f.read()
    logs_to_return = shorten_logs_if_needed(logs)
    logger.info("Build logs for project '%s': {%s}", project_name,
                logs_to_return)
    return logs_to_return

  check_target_logs = os.path.join(oss_fuzz_mcp_config.BASE_TMP_LOGS,
                                   'check-fuzz-run-log.txt')
  if os.path.isfile(check_target_logs):
    os.remove(check_target_logs)
  log_stdout = open(check_target_logs, 'w', encoding='utf-8')
  try:
    subprocess.check_call('python3 infra/helper.py check_build ' + project_name,
                          cwd=oss_fuzz_mcp_config.BASE_OSS_FUZZ_DIR,
                          shell=True,
                          stdout=log_stdout,
                          stderr=subprocess.STDOUT,
                          timeout=60 * 30)
    log_stdout.write("\n\nChecking fuzzers succeeded.\n")
  except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
    logger.info("Check failed for project '%s': {%s}", project_name, str(e))
    log_stdout.write("\n\nChecking fuzzers failed!!\n")
  with open(check_target_logs, 'r', encoding='utf-8') as f:
    logs = f.read()
  logs_to_return = shorten_logs_if_needed(logs)
  logger.info("Check fuzzers for project '%s': {%s}", project_name,
              logs_to_return)
  return logs_to_return


# File operating utilities
#@mcp.tool()
async def list_files(path: str = "") -> str:
  """List all files in the specified directory.
    
    Args:
        path: Optional subdirectory path relative to the base directory
  """
  _internal_delay()
  target_dir = os.path.normpath(path)
  if not target_dir.startswith(oss_fuzz_mcp_config.BASE_DIR):
    return FILE_ACCESS_ERROR

  logger.info("Listing files in directory: %s", target_dir)
  try:
    files = os.listdir(target_dir)
    file_info = []

    for file in files:
      full_path = os.path.join(target_dir, file)
      is_dir = os.path.isdir(full_path)
      size = os.path.getsize(full_path) if not is_dir else "-"
      file_type = "Directory" if is_dir else "File"

      file_info.append({"name": file, "type": file_type, "size": size})

    return_val = json.dumps(file_info, indent=2)
    return return_val
  except Exception as e:
    return f"Error listing files: {str(e)}"


#@mcp.tool()
async def get_file_size(file_path) -> str:
  """Get the size of a file.
    
    Args:
        file_path: Path to the file relative to the base directory

    Returns:
        The size of the file in bytes or an error message.
  """
  _internal_delay()
  target_file = os.path.normpath(file_path)
  if not target_file.startswith(oss_fuzz_mcp_config.BASE_DIR):
    return FILE_ACCESS_ERROR

  logger.info("Getting file size: %s", target_file)
  try:
    if not os.path.isfile(target_file):
      return f"Error: File does not exist or is not a file: {file_path}"

    size = os.path.getsize(target_file)
    return f"File size of {file_path}: {size} bytes"
  except Exception as e:
    return f"Error getting file size: {str(e)}"


#@mcp.tool()
async def read_file(file_path: str, start_idx: int, end_idx: int) -> str:
  """Read the contents of a file. Will read a maximum of 3000 characters
     to control size of content. Use arguments to control which part of file
     to read.

    Args:
        file_path: Path to the file relative to the base directory
        start_idx: character index to start reading from
        end_idx: character index to stop reading (exclusive). If set to -1
                 will read until the end of the file

    Returns:
        The contents of the file or an error message.
  """
  _internal_delay()
  target_file = os.path.normpath(file_path)
  if not target_file.startswith(oss_fuzz_mcp_config.BASE_DIR):
    return FILE_ACCESS_ERROR

  logger.info("Reading file: %s", target_file)
  try:
    if not os.path.isfile(target_file):
      return f"Error: File does not exist or is not a file: {file_path}"

    with open(target_file, 'r', encoding='utf-8') as f:
      content = f.read()
  except Exception as e:
    return f"Error reading file: {str(e)}"

  if end_idx == -1:
    end_idx = len(content)

  buffer_size_to_read = end_idx - start_idx

  if buffer_size_to_read <= 0:
    return f"Error: Invalid indices. Negative size asked for: {buffer_size_to_read}"

  if buffer_size_to_read > 3000:
    return f"Error: Requested size too large: {buffer_size_to_read}. Maximum is 3000 characters."

  try:
    return content[start_idx:end_idx]
  except Exception as e:
    return f"Error extracting content: {str(e)}"


#@mcp.tool()
async def write_file(file_path: str, content: str) -> str:
  """Write content to a file.
    
    Args:
        file_path: Path to the file relative to the base directory
        content: Content to write to the file
  """
  _internal_delay()
  logger.info("Writing to file: %s", file_path)
  target_file = os.path.normpath(file_path)

  if not target_file.startswith(oss_fuzz_mcp_config.BASE_DIR):
    return FILE_ACCESS_ERROR

  try:
    # Create directory if it doesn't exist
    os.makedirs(os.path.dirname(target_file), exist_ok=True)

    with open(target_file, 'w') as f:
      f.write(content)

    return f"Successfully wrote to {file_path}"
  except Exception as e:
    return f"Error writing to file: {str(e)}"


#@mcp.tool()
async def delete_file(file_path: str) -> str:
  """Delete a file.
    
    Args:
        file_path: Path to the file relative to the base directory
  """
  _internal_delay()
  logger.info("Deleting file: %s", file_path)
  target_file = os.path.normpath(file_path)

  if not target_file.startswith(oss_fuzz_mcp_config.BASE_DIR):
    return FILE_ACCESS_ERROR

  try:
    if not os.path.exists(target_file):
      return f"Error: File does not exist: {file_path}"

    if os.path.isdir(target_file):
      os.rmdir(target_file)
      return f"Successfully deleted directory: {file_path}"
    else:
      os.remove(target_file)
      return f"Successfully deleted file: {file_path}"
  except Exception as e:
    return f"Error deleting file: {str(e)}"


#@mcp.tool()
async def search_project_filename(project_name: str, filename: str) -> str:
  """
    Searches for a filename inside the project directory.
    
    Args:
        project_name: Name of the OSS-Fuzz project to search in
        filename: The filename to search for
    
    Returns:
        A string containing the paths of the files with the relevant
        filename, or an error message.
  """
  _internal_delay()
  logger.info('Searching for filename "%s" in project "%s"...', filename,
              project_name)

  if '/' in filename:
    return "Error: Filename should not contain directory separators, only basename."

  files_found = []
  for root, dirs, files in os.walk(
      os.path.join(oss_fuzz_mcp_config.BASE_PROJECTS_DIR, 'projects',
                   project_name)):
    for fname in files:
      if fname == filename:
        full_path = os.path.join(root, fname)
        files_found.append(full_path)
  return '\n'.join(
      files_found
  ) if files_found else f'No files named "{filename}" found in project "{project_name}".'


#@mcp.tool()
async def search_project_file_content(project_name: str,
                                      search_term: str) -> str:
  """
    Searches for a term in the content of files inside the project directory.

    Args:
        project_name: Name of the OSS-Fuzz project to search in.
        search_term: The term to search for in the file contents.

    Returns:
        A string containing the paths of the files that contain the 
        search term and the line in the file the term is found,
        or an error message if no files are found.
    """
  _internal_delay()
  logger.info('Searching for term "%s" in project "%s"...', search_term,
              project_name)

  files_found = []
  for root, _, files in os.walk(
      os.path.join(oss_fuzz_mcp_config.BASE_PROJECTS_DIR, 'projects',
                   project_name)):
    for fname in files:
      full_path = os.path.join(root, fname)
      with open(full_path, 'r', encoding='utf-8') as f:
        content = f.read()
        if search_term in content:
          for lineno, line in enumerate(content.split('\n')):
            if search_term in line:
              files_found.append(f'{full_path}:{lineno}')
  return '\n'.join(
      files_found
  ) if files_found else f'No files containing "{search_term}" found in project "{project_name}".'


#@mcp.tool()
async def get_coverage_of_oss_fuzz_project(project_name):
  """
    Gets the code coverage information for an OSS-Fuzz project.

    Args:
        project_name: Name of the OSS-Fuzz project

    Returns:
        A string containing the code coverage information, or an error message.
  """
  _internal_delay()
  logger.info('Getting coverage for project "%s"...', project_name)

  os.makedirs(oss_fuzz_mcp_config.BASE_TMP_LOGS, exist_ok=True)
  target_logs = os.path.join(oss_fuzz_mcp_config.BASE_TMP_LOGS, 'build-log.txt')
  if os.path.isfile(target_logs):
    os.remove(target_logs)

  log_stdout = open(target_logs, 'w', encoding='utf-8')

  try:
    logger.info("Building OSS-Fuzz project: '%s'", project_name)
    subprocess.check_call(
        'python3 infra/helper.py introspector --coverage-only --seconds=10 ' +
        project_name,
        cwd=oss_fuzz_mcp_config.BASE_OSS_FUZZ_DIR,
        shell=True,
        stdout=log_stdout,
        stderr=subprocess.STDOUT,
        timeout=60 * 20)
  except subprocess.CalledProcessError as e:
    logger.info("Build failed for project '%s': {%s}", project_name, str(e))
  except subprocess.TimeoutExpired:
    logger.info(f"Building project {project_name} timed out.")

  # Extract coverage if we have it.
  coverage_info_file = os.path.join(oss_fuzz_mcp_config.BASE_OSS_FUZZ_DIR,
                                    'build', 'out', project_name, 'report',
                                    'linux', 'summary.json')

  if not os.path.isfile(coverage_info_file):
    return f"Error: Coverage information not found for project '{project_name}'."

  with open(coverage_info_file, 'r', encoding='utf-8') as f:
    oss_fuzz_cov_dict = json.load(f)

  refined_cov_dict = {
      'file-coverage': [],
      'total-coverage': {
          'lines': {
              'count':
                  oss_fuzz_cov_dict['data'][0]['totals']['lines']['count'],
              'covered':
                  oss_fuzz_cov_dict['data'][0]['totals']['lines']['covered'],
              'percent':
                  oss_fuzz_cov_dict['data'][0]['totals']['lines']['percent']
          },
          'functions': {
              'count':
                  oss_fuzz_cov_dict['data'][0]['totals']['functions']['count'],
              'covered':
                  oss_fuzz_cov_dict['data'][0]['totals']['functions']
                  ['covered'],
              'percent':
                  oss_fuzz_cov_dict['data'][0]['totals']['functions']['percent']
          }
      }
  }

  for file_cov in oss_fuzz_cov_dict['data'][0]['files']:
    refined_cov_dict['file-coverage'].append({
        'filename': file_cov['filename'],
        'lines': {
            'count': file_cov['summary']['lines']['count'],
            'covered': file_cov['summary']['lines']['covered'],
            'percent': file_cov['summary']['lines']['percent']
        },
        'functions': {
            'count': file_cov['summary']['functions']['count'],
            'covered': file_cov['summary']['functions']['covered'],
            'percent': file_cov['summary']['functions']['percent']
        }
    })

  logger.info('Refined coverage dict: %s', json.dumps(refined_cov_dict,
                                                      indent=2))

  return json.dumps(refined_cov_dict, indent=2)


def start_mcp_server():
  """Starts the MCP server."""
  global TARGET_PROJECT

  oss_fuzz_target = sys.argv[1]

  TARGET_PROJECT = oss_fuzz_target
  logger.info('OSS-Fuzz MCP server target: %s', oss_fuzz_target)

  try:
    logger.info("Starting MCP server.")
    mcp.run(transport="stdio")
  except KeyboardInterrupt:
    logger.info("Caught KeyboardInterrupt.")
  logger.info('Server shut down.')


if __name__ == "__main__":
  start_mcp_server()
