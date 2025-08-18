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
"""Client for OSS-Fuzz MCP server."""

import asyncio
import os
import shutil
import logging
import httpx
from pydantic_ai import Agent
from pydantic_ai.mcp import MCPServerSSE
import random
import subprocess
import argparse
import logfire

import config as oss_fuzz_mcp_config

logfire.configure(send_to_logfire='if-token-present')
logfire.instrument_pydantic_ai()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger("mcp-server")

MCP_SERVER_URL = "http://localhost:8000/sse"

OSS_FUZZ_SYSTEM_PROMPT = f"""You are an expert software security engineer that is specialized in OSS-Fuzz. OSS-Fuzz
is a framework for managing fuzzing of projects, including building the projects,
writing fuzzing harnesses, and running the fuzzing harnesses.

An OSS-Fuzz project in general consists of a Dockerfile, a build.sh script, and a project.yaml file.
The Dockerfile is used to build the project and the build.sh script is used to build the
fuzzing harnesses. The project.yaml file holds metadata.

OSS-Fuzz builds the projects inside a container and links the fuzzing harnesses
inside the container. The fuzzer executables, and relevant files, are copied to the $OUT directory.

There are three key tasks in OSS-Fuzz:
1. Fixing broken OSS-Fuzz projects. Sometimes the OSS-Fuzz projects fail to build, which
   is likely either a broken Dockerfile, broken build.sh or broken fuzzing harness source codes.
   This often need to be fixed.

2. Creating new OSS-Fuzz projects. This is done by creating a new Dockerfile, build.sh, project.yaml
   and also fuzzing harnesses. This requires studying the project source code and coming up
   with a set up where the fuzzing harnesses exist in the OSS-Fuzz project directory structure.

3. Improving the code coverage of existing OSS-Fuzz projects by adding new fuzzing harnesses or
   extending existing ones.

You are an expert in completing the above tasks.

The OSS-Fuzz source code is available at {oss_fuzz_mcp_config.BASE_OSS_FUZZ_DIR}. The various OSS-Fuzz
projects are available in {oss_fuzz_mcp_config.BASE_OSS_FUZZ_DIR}/projects.

You have access to the MCP tools, which allow you to read and write files, run commands,
and interact with the OSS-Fuzz framework. You must use these tools to complete the tasks.

Each OSS-Fuzz project targets fuzzing of a relevant open source project. Often you need to look at the
source code of this project, which exists in {oss_fuzz_mcp_config.BASE_PROJECTS_DIR}/"the project name"/...
This source code is a local version of the project and *not* the paths that exist in the container.
You should not adjust the files in this directory, but only read and study them. In case you need to
add changes to the source code, then these should be done directly by way of the Dockerfile and build.sh
script. Inside the container, in general the fuzzing harness is placed at $SRC/harness_name... and the project code is in
$SRC/project_name.


A sample structure for an OSS-Fuzz project is rapidjson (located at {oss_fuzz_mcp_config.BASE_OSS_FUZZ_DIR}/projects/rapidjson/)) which has the following relevant files:

Dockerfile:
```
FROM gcr.io/oss-fuzz-base/base-builder
RUN apt-get update && \
    apt-get install -y make autoconf automake libtool cmake libgtest-dev
RUN git clone --depth 1 https://github.com/Tencent/rapidjson.git rapidjson
WORKDIR rapidjson
COPY *.sh fuzzer.cpp $SRC/
```

build.sh
```
export CXXFLAGS="$CXXFLAGS -pthread"

if [[ $CFLAGS = *sanitize=memory* ]]
then
    export CXXFLAGS="$CXXFLAGS -DMSAN"
fi

if [[ $CFLAGS = *sanitize=address* ]]
then
    export CXXFLAGS="$CXXFLAGS -DASAN"
fi

# First build library and tests, which is needed for OSS-Fuzz's Chronos.
mkdir build
cd build
cmake ../
make -j$(nproc)
cd ../

# Build fuzz harness.
$CXX $CXXFLAGS -D_GLIBCXX_DEBUG -I $SRC/rapidjson/include $SRC/fuzzer.cpp $LIB_FUZZING_ENGINE -o $OUT/fuzzer
```

fuzzer.cpp
```
#include <cstdint>
#include <cstddef>
#include <string>
#include <rapidjson/document.h>
#include <rapidjson/prettywriter.h>

#ifdef MSAN
extern "C" {{
    void __msan_check_mem_is_initialized(const volatile void *x, size_t size);
}}
#endif

template<unsigned parseFlags>
void fuzzWithFlags(const std::string &s)
{{
    /* Parse input to rapidjson::Document */
    rapidjson::Document document;
    rapidjson::ParseResult pr = document.Parse<parseFlags>(s.c_str());
    if ( !pr ) {{
        return;
    }}

    /* Convert from rapidjson::Document to string */
    rapidjson::StringBuffer sb;
    rapidjson::PrettyWriter<rapidjson::StringBuffer> writer(sb);
    document.Accept(writer);
    std::string str = sb.GetString();
#ifdef MSAN
    if ( str.size() ) {{
        __msan_check_mem_is_initialized(str.data(), str.size());
    }}
#endif
}}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{{
    const std::string s(data, data + size);

    fuzzWithFlags<rapidjson::kParseDefaultFlags>(s);
    fuzzWithFlags<rapidjson::kParseFullPrecisionFlag>(s);
    fuzzWithFlags<rapidjson::kParseNumbersAsStringsFlag>(s);
    fuzzWithFlags<rapidjson::kParseCommentsFlag>(s);

    return 0;
}}
```

OSS-Fuzz supports multiple languages:
- C
- C++
- Go
- Python
- Java
"""


async def chat_with_agent(prompt: str) -> str:
  """
    Send a message to the LLM with access to the MCP tools.
    
    Args:
        prompt: The user's message
        
    Returns:
        String response from the agent
    """
  try:
    server = MCPServerSSE(url=MCP_SERVER_URL,
                          timeout=5200.0,
                          read_timeout=5000.0)

    agent = Agent(model="openai:gpt-4o", mcp_servers=[server], retries=30)

    # Run the agent with the MCP server context
    async with agent.run_mcp_servers():
      result = await agent.run(prompt)

    return result.output

  except Exception as e:
    return f"Error occurred: {str(e)}"


def initialize_oss_fuzz() -> None:
  """
    Initialize the OSS-Fuzz environment by cloning the OSS-Fuzz repository.
    """
  if not os.path.exists(oss_fuzz_mcp_config.BASE_OSS_FUZZ_DIR):
    logger.info('Cloning OSS-Fuzz repository...')
    subprocess.check_call(
        f'git clone https://github.com/google/oss-fuzz.git {oss_fuzz_mcp_config.BASE_OSS_FUZZ_DIR}',
        shell=True)

  os.makedirs(oss_fuzz_mcp_config.BASE_PROJECTS_DIR, exist_ok=True)


def prepare_oss_fuzz_project(project_name: str) -> bool:
  """Gets the main repo of an OSS-Fuzz project and clones it into our caching folder."""
  # check the project yaml.
  project_yaml = os.path.join(oss_fuzz_mcp_config.BASE_OSS_FUZZ_DIR, 'projects',
                              project_name, 'project.yaml')
  if not os.path.exists(project_yaml):
    logger.warning('Project YAML does not exist: %s', project_yaml)
    return False

  if os.path.isdir(
      os.path.join(oss_fuzz_mcp_config.BASE_PROJECTS_DIR, project_name)):
    return True

  with open(project_yaml, 'r', encoding='utf-8') as f:
    project_data = f.read()
  main_repo = ''
  for line in project_data.split('\n'):
    if line.startswith('main_repo'):
      main_repo = line.replace('main_repo: ', '').strip()
  if not main_repo:
    raise Exception('No main_repo found in project.yaml')
  logger.info('Main repo: %s', main_repo)

  try:
    subprocess.check_call(
        'git clone ' + main_repo + ' ' +
        os.path.join(oss_fuzz_mcp_config.BASE_PROJECTS_DIR, project_name),
        shell=True,
        timeout=60 * 10)
  except subprocess.CalledProcessError as e:
    logger.info(f"Error cloning project {project_name}: {e}")
    return False
  except subprocess.TimeoutExpired:
    logger.info(f"Cloning project {project_name} timed out.")
    return False

  return os.path.isdir(
      os.path.join(oss_fuzz_mcp_config.BASE_PROJECTS_DIR, project_name))


async def does_project_build(project: str) -> bool:
  """Runs OSS-Fuzz build_fuzzers and check_build to validate if project is successful"""
  try:
    subprocess.check_call(
        f'python3 {oss_fuzz_mcp_config.BASE_OSS_FUZZ_DIR}/infra/helper.py build_fuzzers '
        + project,
        cwd=oss_fuzz_mcp_config.BASE_OSS_FUZZ_DIR,
        shell=True,
        timeout=60 * 20)
  except subprocess.CalledProcessError:
    return False
  except subprocess.TimeoutExpired:
    logger.info(f"Building project {project} timed out.")
    return False

  try:
    subprocess.check_call(
        f'python3 {oss_fuzz_mcp_config.BASE_OSS_FUZZ_DIR}/infra/helper.py check_build '
        + project,
        cwd=oss_fuzz_mcp_config.BASE_OSS_FUZZ_DIR,
        shell=True,
        timeout=60 * 10)

  except subprocess.CalledProcessError:
    return False
  except subprocess.TimeoutExpired:
    logger.info(f"Checking build for project {project} timed out.")
    return False

  return True


async def fix_project_build(project: str):
  """Runs an agent to fix the build of an OSS-Fuzz project."""

  response = await chat_with_agent(
      f"""Fix the OSS-Fuzz project {project} that currently has a broken build.
Use the build logs from OSS-Fuzz's project {project} and determine why it fails, then 
proceed to adjust Dockerfile and build.sh scripts until the project builds.

You should edit the files directly in {oss_fuzz_mcp_config.BASE_OSS_FUZZ_DIR}/projects/{project}/....

Once the project builds, then you must ensure the project passes the tests.
This means that "fuzzer-check" must pass for the produced Dockerfile and build.sh.

Do not stop testing new Dockerfile and build.sh scripts until the "fuzzer-check" passes.
If you need access to the files of the project that is being built, then this is available
at the path {oss_fuzz_mcp_config.BASE_PROJECTS_DIR}/{project}/...

The files in this directory are only a copy, and not the files that will exist in the build environment.

Use file operations tools to inspect the files. However, only modify and adjust the files in {oss_fuzz_mcp_config.BASE_OSS_FUZZ_DIR}/projects/{project}/...

Some rules:
- Do not change the ENTRYPOINT of the Dockerfile, it must remain as it is.
- Do not adjust the Dockerfile so it copies files from the {oss_fuzz_mcp_config.BASE_PROJECTS_DIR}/{project}/... directory, as this is not the path that exists in the container.
- If you need to add files to the project directory when inside the container, then add them to the {oss_fuzz_mcp_config.BASE_OSS_FUZZ_DIR}/projects/{project}/ folder and copy via the Dockerfile.
- The "fuzzer-check" must pass.
- Continue adjusting the files in {oss_fuzz_mcp_config.BASE_OSS_FUZZ_DIR}/projects/{project}/ until "fuzzer-check" passes.
""")

  fix_success = await does_project_build(project)
  return response, fix_success


def _get_all_broken_oss_fuzz_projects(language: str = '') -> list[str]:
  """Gets the projects that are failing to build in OSS-Fuzz."""
  OSS_FUZZ_BUILD_STATUS_URL = 'https://oss-fuzz-build-logs.storage.googleapis.com'
  FUZZ_BUILD_JSON = 'status.json'
  fuzz_build_url = OSS_FUZZ_BUILD_STATUS_URL + '/' + FUZZ_BUILD_JSON

  raw_fuzz_builds = httpx.get(fuzz_build_url)
  if raw_fuzz_builds.status_code != 200:
    raise Exception(
        f"Failed to fetch OSS-Fuzz build status: {raw_fuzz_builds.status_code}")
  fuzz_builds = raw_fuzz_builds.json()
  broken_projects = []
  for project in fuzz_builds.get('projects', []):

    if len(project.get('history', [])) <= 4:
      continue

    history = project['history']
    # Ensure the latest three build are failing, as we don't want to "fix" projects
    # that spurious fail. This happens due to network issues, for example.
    if history[0]['success'] or history[1]['success'] or history[2]['success']:
      continue

    # Make sure the project actually exists in the OSS-Fuzz repository.
    # We need to do this because Clusterfuzz may keep some projects rolling
    # withouth them being in OSS-Fuzz any longer.
    project_path = os.path.join(oss_fuzz_mcp_config.BASE_OSS_FUZZ_DIR,
                                'projects', project['name'])
    if not os.path.exists(project_path):
      continue

    if language:
      # Check which language
      project_yaml = os.path.join(project_path, 'project.yaml')
      if not os.path.exists(project_yaml):
        logger.info(
            f"Project {project['name']} does not have a project.yaml file, skipping."
        )
        continue
      with open(project_yaml, 'r', encoding='utf-8') as f:
        project_data = f.read()
      project_language = ''
      for line in project_data.split('\n'):
        if line.startswith('language:'):
          project_language = line.replace('language:', '').strip().lower()
          break
      if project_language != language.lower():
        continue

    broken_projects = [project['name']] + broken_projects
  return broken_projects


async def add_run_tests_command(project_name: str):
  """Adds a run-tests.sh command for a specific OSS-Fuzz project."""
  project_path = os.path.join(oss_fuzz_mcp_config.BASE_OSS_FUZZ_DIR, 'projects',
                              project_name)
  if not os.path.exists(project_path):
    logger.warning("Project %s does not exist in OSS-Fuzz.", project_name)
    return
  if not prepare_oss_fuzz_project(project_name):
    logger.warning("Failed to prepare OSS-Fuzz project %s.", project_name)
    return

  run_tests_path = os.path.join(project_path, 'run_tests.sh')
  if not os.path.exists(run_tests_path):
    with open(run_tests_path, 'w', encoding='utf-8') as f:
      f.write("#!/bin/bash\n")
      f.write("echo 'Running tests for project: {}'\n".format(project_name))

  dockerfile_path = os.path.join(project_path, 'Dockerfile')
  if not os.path.exists(dockerfile_path):
    logger.info(f"Dockerfile does not exist for project {project_name}.")
    return
  with open(dockerfile_path, 'r', encoding='utf-8') as f:
    if 'run_tests.sh' not in f.read():
      should_add = True
    else:
      should_add = False

  if should_add:
    with open(dockerfile_path, 'a', encoding='utf-8') as f:
      f.write("COPY run_tests.sh $SRC/\n")
      f.write("RUN chmod +x $SRC/run_tests.sh\n")

  os.chmod(run_tests_path, 0o755)

  response = await chat_with_agent(f"""
You are an expert software security engineer that is specialized in OSS-Fuzz.
You are tasked with adding a run_tests.sh script to an OSS-Fuzz project.
This script should run the tests of the project, and ensure that the project is working correctly.
The run_tests.sh script should be placed in the project directory at {oss_fuzz_mcp_config.BASE_OSS_FUZZ_DIR}/projects/{project_name}/run_tests.sh.
You must ensure that the run_tests.sh script is executable and runs the tests of the project.
The run_tests.sh script should be placed in the project directory at {oss_fuzz_mcp_config.BASE_OSS_FUZZ_DIR}/projects/{project_name}/run_tests.sh.
You must ensure that the run_tests.sh script is executable and runs the tests of the project.
You should assume the run_tests.sh script runs after the project is build, and that the starting working
directory of the run_tests.sh script is the WORKDIR of the Dockerfile ($SRC if not otherwise specified).

Your task is to fix the run_tests.sh script for {project_name} so it runs the tests of the project and also passes the `run-tests-check`.

You are working on the OSS-Fuzz project {project_name}.

You must ensure the check `run-tests-check` passes! Continue creating a new run_tests.sh script until the check passes.

You must adjust the file in {oss_fuzz_mcp_config.BASE_OSS_FUZZ_DIR}/projects/{project_name}/run_tests.sh to execute the tests.

You must run the `run-tests-check` after adjusting the script.""")

  logger.info(
      f"Added run_tests.sh for project {project_name}. Response: {response}")


async def fix_oss_fuzz_projects(projects_to_fix=None,
                                max_projects_to_fix=4,
                                language=''):
  """Fixes the build of a list of OSS-Fuzz projects."""

  if projects_to_fix is None:
    # Get list of all OSS-Fuzz projects that are broken.
    broken_oss_fuzz_projects = _get_all_broken_oss_fuzz_projects(language)
    random.shuffle(broken_oss_fuzz_projects)
    logger.info('Total number of broken OSS-Fuzz projects: %d',
                len(broken_oss_fuzz_projects))
    if len(broken_oss_fuzz_projects) > max_projects_to_fix:
      broken_oss_fuzz_projects = broken_oss_fuzz_projects[:max_projects_to_fix]
  else:
    broken_oss_fuzz_projects = projects_to_fix

  logger.info('Projects to fix: %s', broken_oss_fuzz_projects)
  if not broken_oss_fuzz_projects:
    logger.info('No broken OSS-Fuzz projects to fix.')
    return

  responses = []
  for project in broken_oss_fuzz_projects:
    logger.info('Trying to fix project: %s', project)
    try:
      if not prepare_oss_fuzz_project(project):
        continue
    except:
      continue
    response, fix_success = await fix_project_build(project)
    responses.append({
        'project': project,
        'response': response,
        'fix_success': fix_success
    })

    with open(os.path.join(oss_fuzz_mcp_config.BASE_DIR, 'build-responses.txt'),
              'w') as f:
      for resp in responses:
        f.write('-' * 60 + '\n')
        f.write(f"{resp['project']} : {resp['fix_success']}\n")
        f.write(f"Agent: {resp['response']}\n")


async def initiate_project_creation(project: str, project_repo: str,
                                    language: str):
  """Runs an agent to create an OSS-Fuzz project."""

  if language == 'go':
    extra_text = """
A sample build.sh script for a Go OSS-Fuzz project is:

```sh
mv $SRC/fuzz_pageparser.go $SRC/hugo/parser/pageparser/

compile_go_fuzzer github.com/gohugoio/hugo/parser/pageparser FuzzParseFrontMatterAndContent FuzzParseFrontMatterAndContent
```

and a sample go fuzzer is:

```go
package pageparser

import "bytes"

func FuzzParseFrontMatterAndContent(data []byte) int {
	ParseFrontMatterAndContent(bytes.NewReader(data))
	return 1
}
```

You must use the `compile_go_fuzzer` command which exists inside the OSS-Fuzz container.
To debug semantics of this if needed, you should build the project and extract the logs. The first
argument to `compile_go_fuzzer` is the package path, and the second argument is the fuzzer name.
"""
  else:
    extra_text = ""

  response = await chat_with_agent(
      f"""You are an expert software security engineer and you are tasked with creating an OSS-Fuzz project.
I have set up an initial project structure at {oss_fuzz_mcp_config.BASE_OSS_FUZZ_DIR}/projects/{project}/. This structure
includes a Dockerfile, build.sh, and project.yaml file. The Dockerfile clones the target
project repository ({project_repo}) and the build.sh file is empty. Your task is to
fill in the empty build.sh file with the necessary commands to build the project.
The Dockerfile should set up the relevant dependencies, but it should continue to
inherit FROM the base builder image as already set.

You should:
(1) fix the build.sh so it builds the project correctly, using CC, CXX, CFLAGS and CXXFLAGS for compilation.
(2) add at least one fuzzing harness. This should be added in the {oss_fuzz_mcp_config.BASE_OSS_FUZZ_DIR}/projects/{project}/ directory
and copied into the contained using the Dockerfile, where it will be build by the build.sh script.

You must ensure when the fuzzing harness is linked that the $LIB_FUZZING_ENGINE environment variable
is included in the link command. The build.sh script must make sure to copy out the fuzzers build
to the $OUT/ directory.

You must continue this session until the OSS-Fuzz project {project} builds correctly and the
\"fuzzer-check\" must pass.

This is a project in the {language} programming language, so you must ensure the fuzzing
harness is written in {language} and the build.sh script is set up to compile the project.

{extra_text}

The project repository source code is available at {oss_fuzz_mcp_config.BASE_PROJECTS_DIR}/{project}/.
This source code is a local version of the project and *not* the paths that exist in the container. You should not adjust the files
in this directory, but only read them. In case you need to add changes to the source code,
then these should be done directly by way of the Dockerfile and build.sh script. Inside the container,
in general the fuzzing harness is placed at $SRC/harness_name... and the project code is in
$SRC/project_name.

You must add at least one fuzzing harness to the OSS-Fuzz project {project}, and ensure it
fully works.

Use the file reading and writing tools to create the necessary files in the {oss_fuzz_mcp_config.BASE_OSS_FUZZ_DIR}/projects/{project}/ directory.
Then, run the build_fuzzers and check_build commands to ensure the project builds correctly.
Repeat this until the project builds successfully and the fuzzer-check passes.
The project must build success fully and the fuzzer-check must pass. If they do not pass, then
you must refine the OSS-Fuzz project until it does.
""")

  fix_success = await does_project_build(project)
  logger.info("Project %s creation response: %s. Fix success: %s", project,
              response, fix_success)

  return response, fix_success


def prepare_new_oss_fuzz_project(project_name: str, project_url: str) -> bool:
  """Gets the main repo of an OSS-Fuzz project and clones it into our caching folder."""
  if os.path.isdir(
      os.path.join(oss_fuzz_mcp_config.BASE_PROJECTS_DIR, project_name)):
    return True

  try:
    subprocess.check_call(
        'git clone ' + project_url + ' ' +
        os.path.join(oss_fuzz_mcp_config.BASE_PROJECTS_DIR, project_name),
        shell=True,
        timeout=60 * 10)
  except subprocess.CalledProcessError as e:
    logger.info("Error cloning project %s: %s", project_name, e)
    return False
  except subprocess.TimeoutExpired:
    logger.info("Cloning project %s timed out.", project_name)
    return False

  return os.path.isdir(
      f'{oss_fuzz_mcp_config.BASE_PROJECTS_DIR}/{project_name}')


async def create_oss_fuzz_integration_for_project(project_url: str,
                                                  project_language: str):
  """Creates an integration for a specific OSS-Fuzz project."""
  # This function would typically create a new MCP tool for the project
  # and register it with the MCP server.
  # For now, we will just print the project URL.
  logger.info(f"Creating OSS-Fuzz integration for project: {project_url}")
  # Here you would implement the logic to create the integration.

  oss_fuzz_project_name = project_url.split('/')[-1]
  if not oss_fuzz_project_name:
    raise ValueError("Project URL does not contain a valid project name.")
  oss_fuzz_path = os.path.join(oss_fuzz_mcp_config.BASE_OSS_FUZZ_DIR,
                               'projects', oss_fuzz_project_name)
  if os.path.isdir(oss_fuzz_path):
    shutil.rmtree(oss_fuzz_path)

  os.makedirs(oss_fuzz_path)
  dockerfile_path = os.path.join(oss_fuzz_path, 'Dockerfile')
  build_sh_path = os.path.join(oss_fuzz_path, 'build.sh')
  project_yaml_path = os.path.join(oss_fuzz_path, 'project.yaml')

  base_image = ''
  project_language = project_language.lower()

  if project_language == 'c':
    base_image = 'gcr.io/oss-fuzz-base/base-builder'
  elif project_language == 'c++':
    base_image = 'gcr.io/oss-fuzz-base/base-builder'
  elif project_language == 'go':
    base_image = 'gcr.io/oss-fuzz-base/base-builder-go'

  # Dockerfile
  with open(dockerfile_path, 'w') as f:
    dockerfile_content = f"""
FROM {base_image}
RUN apt-get update && apt-get install -y make autoconf automake libtool
RUN git clone {project_url} /src/{oss_fuzz_project_name}
WORKDIR /src/{oss_fuzz_project_name}
COPY build.sh $SRC/build.sh
"""

    f.write(dockerfile_content)

  # Build script
  with open(build_sh_path, 'w') as f:
    build_sh_content = f"""#!/bin/bash -eux
# Empty build script for now. This needs to be filled with the actual build commands."""
    f.write(build_sh_content)

  # Project YAML
  with open(project_yaml_path, 'w') as f:
    project_yaml_content = f"""\
homepage: "{project_url}"
language: {project_language}
primary_contact: "david@adalogics.com"
main_repo: "{project_url}"
"""
    f.write(project_yaml_content)

  prepare_new_oss_fuzz_project(oss_fuzz_project_name, project_url)

  # First, create a template setup for the project.
  # Use a local directory with the project clone,
  await initiate_project_creation(oss_fuzz_project_name, project_url,
                                  project_language)


def parse_arguments():
  """Parse command line arguments."""

  parser = argparse.ArgumentParser(description="OSS-Fuzz MCP Client")

  subparsers = parser.add_subparsers(dest='command')

  # Fix builds command
  fix_builds = subparsers.add_parser(
      'fix-builds',
      help='Fix the builds of OSS-Fuzz projects that are currently broken.')

  fix_builds.add_argument('--max-projects',
                          type=int,
                          default=4,
                          help='Maximum number of projects to fix (default: 4)')

  fix_builds.add_argument('--language',
                          help='Filter projects by language (e.g., c, c++, go)',
                          default='')
  fix_builds.add_argument(
      '--projects',
      nargs='*',
      help=
      'List of specific projects to fix. If not provided, random broken projects will be selected.'
  )

  # Create initial OSS-Fuzz project command.
  create_project = subparsers.add_parser(
      'create-project',
      help=
      'Create an initial OSS-Fuzz project with a given repository URL and language.'
  )
  create_project.add_argument(
      'project_url',
      type=str,
      help='The URL of the project repository to create an OSS-Fuzz project for.'
  )
  create_project.add_argument(
      'language',
      type=str,
      help='The programming language of the project (e.g., c, c++, go).')

  # Command to add run_tests.sh
  add_run_tests_parser = subparsers.add_parser(
      'run-tests', help='Add run-tests.sh command for specific project')
  add_run_tests_parser.add_argument(
      'project_name',
      type=str,
      help='The name of the project to add run-tests.sh command for.')

  return parser.parse_args()


async def main():
  """Main function to demonstrate the client usage"""

  args = parse_arguments()

  initialize_oss_fuzz()
  if args.command == 'fix-builds':
    await fix_oss_fuzz_projects(args.projects, args.max_projects, args.language)
  elif args.command == 'create-project':
    logger.info('Creating OSS-Fuzz project for URL:', args.project_url)
    await create_oss_fuzz_integration_for_project(args.project_url,
                                                  args.language)
  elif args.command == 'run-tests':
    await add_run_tests_command(args.project_name)


if __name__ == "__main__":
  asyncio.run(main())
