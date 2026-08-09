# ARVO reproducer
# Paper: https://arxiv.org/abs/2408.02153
# ARVO Implementation: https://github.com/n132/ARVO
# Neil — May 5, 2025 — Seattle, USA
# Jordi — July 30, 2025
"""ARVO reproducer module.

This module reproduces a vulnerability and its fix on OSS-Fuzz.
Login gcloud:
    $ gcloud auth application-default login 

Classes:
    BuildData: Named tuple for build configuration data.
    
Functions:
    Main reproducing functions and utilities for OSS-Fuzz
    vulnerability reproduction.
"""

import argparse
import json
import logging
import os
import re
import subprocess
import tempfile
import time
from bisect import bisect_right
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

import requests
from dateutil.parser import parse
from google.cloud import storage
from dataclasses import dataclass

from arvo_data import (extra_scripts, fix_build_script, fix_dockerfile,
                       skip_component, special_component, update_resource_info)
from arvo_utils import (DockerfileModifier, VersionControlTool, check_call,
                        clean_dir, clone, docker_build, docker_run, execute,
                        hg_clone, leave_ret, svn_clone, OSS_ERR, OSS_OUT,
                        OSS_WORK, PNAME_TABLE)

# Global storage client
storage_client: storage.Client | None = None


@dataclass
class BuildData:
  project_name: str
  engine: str
  sanitizer: str
  architecture: str


def parse_oss_fuzz_report(report_text: bytes,
                          local_id: int) -> dict[str, Any] | bool:
  """Parse OSS-Fuzz report text and extract relevant information.
    
    Args:
        report_text: Raw report text as bytes.
        local_id: Local ID of the issue.
        
    Returns:
        Dictionary containing parsed report data, or False if parsing fails.
    """
  text = report_text.decode(
      'unicode_escape', errors='ignore')  # decode escaped unicode like \u003d

  def extract(pattern: str, default: str = '') -> str:
    """Extract information using regex pattern."""
    match = re.search(pattern, text)
    if not match:
      if default == '':
        logging.error(f"FAILED to PARSE {pattern} {local_id=}")
        exit(1)
      else:
        return default
    return match.group(1).strip()

  result = {
      "project":
          extract(r'(?:Target|Project):\s*(\S+)', 'NOTFOUND'),
      "job_type":
          extract(r'Job Type:\s*(\S+)'),
      "platform":
          extract(r'Platform Id:\s*(\S+)', 'linux'),
      "crash_type":
          extract(r'Crash Type:\s*(.+)'),
      "crash_address":
          extract(r'Crash Address:\s*(\S+)'),
      "severity":
          extract(r'Security Severity:\s*(\w+)', 'Medium'),
      "regressed":
          extract(r'(?:Regressed|Crash Revision):\s*(https?://\S+)',
                  "NO_REGRESS"),
      "reproducer":
          extract(r'(?:Minimized Testcase|Reproducer Testcase|Download).*:'
                  r'\s*(https?://\S+)'),
      "verified_fixed":
          extract(r'(?:fixed in|Fixed:)\s*(https?://\S+revisions\S+)',
                  'NO_FIX'),
      "localId":
          local_id
  }

  sanitizer_map = {
      "address (ASAN)": "address",
      "memory (MSAN)": "memory",
      "undefined (UBSAN)": "undefined",
      "asan": "address",
      "msan": "memory",
      "ubsan": "undefined",
  }

  fuzz_target = extract(r'(?:Fuzz Target|Fuzz target binary):\s*(\S+)',
                        'NOTFOUND')

  if len(result['job_type'].split("_")) == 2:
    return False
  else:
    result['sanitizer'] = sanitizer_map[result['job_type'].split("_")[1]]

  if fuzz_target != 'NOTFOUND':
    result['fuzz_target'] = fuzz_target
  if result['project'] == "NOTFOUND":
    result['project'] = result['job_type'].split("_")[-1]

  return result


def fetch_issue(local_id: int | str) -> dict[str, Any] | bool:
  """Fetch issue information from OSS-Fuzz tracker.
    
    Args:
        local_id: Local ID of the issue to fetch.
        
    Returns:
        Dictionary containing issue information, or False if fetch fails.
    """
  # TODO: Replace this with proper issue tracker API calls
  url = (f'https://issues.oss-fuzz.com/action/issues/{local_id}/'
         f'events?currentTrackerId=391')
  session = requests.Session()

  # Step 1: Get the token from the cookie
  session.get("https://issues.oss-fuzz.com/")
  xsrf_token = session.cookies.get("XSRF_TOKEN")

  headers = {
      'accept':
          'application/json, text/plain, */*',
      'accept-language':
          'en,zh-CN;q=0.9,zh;q=0.8,ar;q=0.7',
      'priority':
          'u=1, i',
      'referer':
          'https://issues.oss-fuzz.com/',
      'sec-ch-ua':
          '"Chromium";v="134", "Not:A-Brand";v="24", "Google Chrome";v="134"',
      'sec-ch-ua-mobile':
          '?0',
      'sec-ch-ua-platform':
          '"Linux"',
      'sec-fetch-dest':
          'empty',
      'sec-fetch-mode':
          'cors',
      'sec-fetch-site':
          'same-origin',
      'user-agent':
          'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 '
          '(KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36',
      'X-XSRF-Token':
          xsrf_token
  }

  response = session.get(url, headers=headers)
  raw_text = response.content

  try:
    result = parse_oss_fuzz_report(raw_text, int(local_id))
  except Exception:
    logging.error(f"FAIL on {local_id}, skip")
    return False

  return result


def parse_job_type(job_type: str) -> dict[str, Any]:
  """Parse job type string into components.
    
    Args:
        job_type: Job type string from OSS-Fuzz.
        
    Returns:
        Dictionary containing parsed job type components.
    """
  parts = job_type.split('_')
  remainder = []
  parsed = {}

  while len(parts) > 0:
    part = parts.pop(0)
    if part in ['afl', 'honggfuzz', 'libfuzzer']:
      parsed['engine'] = part
    elif part in ['asan', 'ubsan', 'msan']:
      parsed['sanitizer'] = part
    elif part == 'i386':
      parsed['arch'] = part
    elif part == 'untrusted':
      parsed['untrusted'] = True
    else:
      remainder.append(part)

  if len(remainder) > 0:
    parsed['project'] = '_'.join(remainder)
  if 'arch' not in parsed:
    parsed['arch'] = 'x86_64'
  if 'engine' not in parsed:
    parsed['engine'] = 'none'
  if 'untrusted' not in parsed:
    parsed['untrusted'] = False

  return parsed


def download_build_artifacts(metadata: dict[str, Any], url: str,
                             outdir: Path) -> list[str] | bool:
  """Download build artifacts from Google Cloud Storage.
    
    Args:
        metadata: Issue metadata containing build information.
        url: URL to download artifacts from.
        outdir: Output directory for downloaded files.
        
    Returns:
        List of downloaded file paths on success, False on failure.
    """
  global storage_client
  if storage_client is None:
    storage_client = storage.Client()

  bucket_map = {
      "libfuzzer_address_i386": "clusterfuzz-builds-i386",
      "libfuzzer_memory_i386": "clusterfuzz-builds-i386",
      "libfuzzer_undefined_i386": "clusterfuzz-builds-i386",
      "libfuzzer_address": "clusterfuzz-builds",
      "libfuzzer_memory": "clusterfuzz-builds",
      "libfuzzer_undefined": "clusterfuzz-builds",
      "afl_address": "clusterfuzz-builds-afl",
      "honggfuzz_address": "clusterfuzz-builds-honggfuzz",
  }

  sanitizer_map = {
      "address (ASAN)": "address",
      "memory (MSAN)": "memory",
      "undefined (UBSAN)": "undefined",
      "asan": "address",
      "msan": "memory",
      "ubsan": "undefined",
      "address": "address",
      "memory": "memory",
      "undefined": "undefined",
      None: "",
  }

  job_name = metadata["job_type"]
  job = parse_job_type(job_name)

  # These don't have any build artifacts
  if job['untrusted'] or job['engine'] == 'none':
    return False

  # Prefer the info from the job name, since the metadata
  # format has changed several times.
  if 'project' in metadata:
    project = metadata["project"]
  else:
    project = job['project']

  if 'sanitizer' in metadata:
    sanitizer = sanitizer_map[metadata["sanitizer"]]
    assert sanitizer == sanitizer_map[job['sanitizer']]
  else:
    sanitizer = sanitizer_map[job['sanitizer']]

  fuzzer = job['engine']
  bucket_string = f"{fuzzer}_{sanitizer}"
  if job['arch'] == 'i386':
    bucket_string += '_i386'

  assert bucket_string in bucket_map
  bucket_name = bucket_map[bucket_string]

  # Grab the revision from the URL
  urlparams = parse_qs(urlparse(url).query)

  if 'revision' in urlparams:
    revision = urlparams['revision'][0]
  elif 'range' in urlparams:
    revision = urlparams['range'][0].split(':')[1]
  else:
    return False

  zip_name = f'{project}-{sanitizer}-{revision}.zip'
  srcmap_name = f'{project}-{sanitizer}-{revision}.srcmap.json'
  zip_path = f'{project}/{zip_name}'
  srcmap_path = f'{project}/{srcmap_name}'
  downloaded_files = []
  bucket = storage_client.bucket(bucket_name)

  for path, name in [(srcmap_path, srcmap_name)]:
    download_path = outdir / name

    if download_path.exists():
      logging.info(f'Skipping {name} (already exists)')
      downloaded_files.append(download_path)
      continue

    blob = bucket.blob(path)
    if not blob.exists():
      logging.info(f'Skipping {name} (not found)')
      continue

    blob.download_to_filename(str(download_path))
    logging.info(f'Downloaded {name}')
    downloaded_files.append(download_path)

  return [str(f) for f in downloaded_files]


def get_project_name(issue: dict[str, Any], srcmap: str | Path) -> str | bool:
  """Get project name from issue and srcmap data.
    
    Args:
        issue: Issue dictionary containing project information.
        srcmap: Path to the srcmap file.
        
    Returns:
        Project name on success, False on failure.
    """
  if 'project' not in issue:
    logging.error("[FAILED] to get project field in issue")
    return False
  else:
    project_name = issue['project']

  if project_name in PNAME_TABLE:
    return PNAME_TABLE[project_name]  # handling special cases

  with open(srcmap, encoding='utf-8') as f:
    info1 = json.load(f)

  expected_name = "/src/" + project_name
  if expected_name in info1:
    return project_name
  else:
    logging.error(
        f"Failed to locate the main component, plz add that to pname_table")
    return False


def get_language(project_dir: Path) -> str | bool:
  """Get programming language from project.yaml file.
    
    Args:
        project_dir: Path to the project directory.
        
    Returns:
        Language string on success, False on failure.
    """
  project_yaml = project_dir / "project.yaml"
  if not project_yaml.exists():
    return False

  with open(project_yaml, encoding='utf-8') as f:
    content = f.read()

  matches = re.findall(r'language\s*:\s*([^\s]+)', content)
  if len(matches) != 1:
    logging.error(f"[!] Get more than one languages")
    return False

  return str(matches[0])


def get_sanitizer(fuzzer_sanitizer: str) -> str | bool:
  """Convert fuzzer sanitizer short name to full name.
    
    Args:
        fuzzer_sanitizer: Short sanitizer name (asan, msan, ubsan).
        
    Returns:
        Full sanitizer name on success, False on failure.
    """
  sanitizer_map = {'asan': "address", 'msan': 'memory', 'ubsan': 'undefined'}

  return sanitizer_map.get(fuzzer_sanitizer, False)


def download_poc(issue: dict[str, Any], path: Path, name: str) -> Path | bool:
  """Download proof-of-concept file from issue.
    
    Args:
        issue: Issue dictionary containing reproducer URL.
        path: Directory to save the POC file.
        name: Name for the downloaded file.
        
    Returns:
        Path to downloaded file on success, False on failure.
    """
  session = requests.Session()
  url = issue['reproducer']
  response = session.head(url, allow_redirects=True)

  if response.status_code != 200:
    return False

  reproducer_path = path / name
  response = session.get(url)

  if response.status_code != 200:
    return False

  reproducer_path.write_bytes(response.content)
  return reproducer_path


def prepare_ossfuzz(project_name: str,
                    commit_date: str | datetime) -> tuple[Path, Path] | bool:
  """Prepare OSS-Fuzz repository for the specified project and date.
    
    Args:
        project_name: Name of the project.
        commit_date: Target commit date or commit hash.
        
    Returns:
        Tuple of (temp_dir, project_dir) on success, False on failure.
    """
  # 1. Clone OSS Fuzz
  tmp_dir = clone("https://github.com/google/oss-fuzz.git", name="oss-fuzz")
  if tmp_dir is False:
    return False

  # 2. Get the Commit Close to Commit_Date
  tmp_oss_fuzz_dir = tmp_dir / "oss-fuzz"

  if isinstance(commit_date, str):
    oss_fuzz_commit = commit_date
  else:
    # Remove the cmd variable and use the list directly
    result = execute([
        'git', 'log', '--before=' + commit_date.isoformat(), '-n1',
        '--format=%H'
    ], tmp_oss_fuzz_dir)
    if result.success and result.output:
      oss_fuzz_commit = result.output.strip()
    else:
      oss_fuzz_commit = False

    if oss_fuzz_commit is False:
      cmd = ['git', 'log', '--reverse', '--format=%H']
      result = execute(cmd, tmp_oss_fuzz_dir)
      if result.success and result.output:
        oss_fuzz_commit = result.output.splitlines()[0].strip()
      else:
        oss_fuzz_commit = False

      if oss_fuzz_commit is False:
        logging.error('Failed to get oldest oss-fuzz commit')
        return leave_ret(False, tmp_dir)

  # 3. Reset OSS Fuzz
  gt = VersionControlTool(tmp_oss_fuzz_dir)
  if not gt.reset(oss_fuzz_commit):
    logging.error("Failed to Reset OSS-Fuzz")
    return leave_ret(False, tmp_dir)

  # 4. Locate Project Dir
  tmp_list = [x for x in tmp_oss_fuzz_dir.iterdir() if x.is_dir()]
  if tmp_oss_fuzz_dir / "projects" in tmp_list:
    proj_dir = tmp_oss_fuzz_dir / "projects" / project_name
  elif tmp_oss_fuzz_dir / "targets" in tmp_list:
    proj_dir = tmp_oss_fuzz_dir / "targets" / project_name
  else:
    logging.error(f"Failed to locate the project({project_name}) in oss-fuzz")
    return leave_ret(False, tmp_dir)

  return (tmp_dir, proj_dir)


def rebase_dockerfile(dockerfile_path: str | Path, commit_date: str) -> bool:
  """Rebase dockerfile to use historical base image.
    
    Args:
        dockerfile_path: Path to the Dockerfile to rebase.
        commit_date: Target commit date for base image.
        
    Returns:
        True if rebase succeeded, False otherwise.
    """

  def _get_base(date: str,
                repo: str = "gcr.io/oss-fuzz-base/base-builder") -> str:
    """Get base image hash for the specified date."""
    cache_name = repo.split("/")[-1]
    cache_file = f"/tmp/{cache_name}_cache.json"
    cache_ttl = 86400  # 24 hours
    result_json = []

    if os.path.exists(cache_file) and (
        time.time() - os.path.getmtime(cache_file)) < cache_ttl:
      with open(cache_file, 'r', encoding='utf-8') as f:
        result_json = json.load(f)
    else:
      cmd = [
          "gcloud", "container", "images", "list-tags", repo, "--format=json",
          "--sort-by=timestamp"
      ]
      result = execute(cmd)
      if result.success and result.output:
        result_json = json.loads(result.output)
        with open(cache_file, 'w', encoding='utf-8') as f:
          f.write(json.dumps(result_json, indent=4))
      else:
        return ""

    timestamps = []
    for item in result_json:
      timestamps.append(int(parse(item['timestamp']['datetime']).timestamp()))

    target_ts = int(parse(date).timestamp())
    return result_json[bisect_right(timestamps, target_ts - 1) -
                       1]['digest'].split(":")[1]

  # Load the Dockerfile
  try:
    with open(dockerfile_path, encoding='utf-8') as f:
      data = f.read()
  except IOError:
    logging.error(f"No such a dockerfile: {dockerfile_path}")
    return False

  # Locate the Repo
  match = re.search(r'FROM .*', data)
  if match is None:
    logging.error("Failed to get the base-image: {dockerfile_path}")
    return False
  else:
    repo = match[0][5:]

  if "@sha256" in repo:
    repo = repo.split("@sha256")[0]
  if repo == 'ossfuzz/base-builder' or repo == 'ossfuzz/base-libfuzzer':
    repo = "gcr.io/oss-fuzz-base/base-builder"
  if ":" in repo:
    repo = repo.split(":")[0]

  image_hash = _get_base(commit_date, repo)

  # We insert update since some old dockerfile doesn't have that line
  data = re.sub(
      r"FROM .*",
      f"FROM {repo}@sha256:" + image_hash + "\nRUN apt-get update -y\n", data)

  with open(dockerfile_path, 'w', encoding='utf-8') as f:
    f.write(data)

  return True


def update_revision_info(dockerfile: str | Path, src_path: str,
                         item: dict[str, Any], commit_date: datetime | Path,
                         approximate: str) -> bool:
  """Update revision information in dockerfile.
    
    Args:
        dockerfile: Path to the dockerfile.
        src_path: Source path in the dockerfile.
        item: Item information containing URL, revision, and type.
        commit_date: Target commit date or path for replacement mode.
        approximate: Approximation direction ('+' or '-').
        
    Returns:
        True if update succeeded, False otherwise.
    """
  item_url = item['url']
  item_rev = item['rev']
  item_type = item['type']
  dft = DockerfileModifier(dockerfile)

  if item_url.startswith("http:"):
    keyword = item_url[4:]
  elif item_url.startswith("https:"):
    keyword = item_url[5:]
  else:
    keyword = item_url

  hits, line_count = dft.get_line(keyword)
  # mismatch
  if len(hits) != 1:
    return False

  line = hits[0]
  if item_type == 'git':
    pattern = re.compile(rf"{item_type}\s+clone")
  elif item_type == 'hg':
    pattern = re.compile(rf"{item_type}\s+clone")
  elif item_type == 'svn':
    pattern = re.compile(rf"RUN\s+svn\s+(co|checkout)+")
  else:
    logging.error("NOT supported protocol")
    return False

  if len(pattern.findall(line)) != 1:  # mismatch
    return False

  if isinstance(commit_date, Path):
    rep_path = commit_date
    # Replace mode: for bisection
    # Replace the original line with ADD/COPY command
    # Then RUN init/update the submodule
    dft.replace_line_at(line_count - 1, f"ADD {rep_path.name} {src_path}")
    dft.insert_line_at(
        line_count, f"RUN bash -cx 'pushd {src_path} ;(git submodule init && "
        f"git submodule update --force) ;popd'")
    dft.flush()
    return True
  else:
    # Insertion Mode
    if item_type == "git":
      if approximate == '-':
        dft.insert_line_at(
            line_count, f"RUN bash -cx 'pushd {src_path} ; "
            f"(git reset --hard {item_rev}) || "
            f"(commit=$(git log --before='{commit_date.isoformat()}' "
            f"--format='%H' -n1) && "
            f"git reset --hard $commit || exit 99) ; "
            f"(git submodule init && git submodule update --force) ;popd'")
      else:
        dft.insert_line_at(
            line_count, f"RUN bash -cx 'pushd {src_path} ; "
            f"(git reset --hard {item_rev}) || "
            f"(commit=$(git log --since='{commit_date.isoformat()}' "
            f"--format='%H' --reverse | head -n1) && "
            f"git reset --hard $commit || exit 99) ; "
            f"(git submodule init && git submodule update --force) ;popd'")
    elif item_type == 'hg':
      # TODO: support approximate
      dft.insert_line_at(
          line_count, f'RUN bash -cx "pushd {src_path} ; '
          f'(hg update --clean -r {item_rev} && '
          f'hg purge --config extensions.purge=)|| exit 99 ; popd"')
    elif item_type == "svn":
      # TODO: support approximate
      dft.replace(pattern, f"RUN svn checkout -r {item_rev}")
    else:
      logging.error("Failed to support {item_type}")
      return False

    dft.flush()
    return True


def build_fuzzers_impl(local_id: int | str,
                       project_dir: Path,
                       engine: str,
                       sanitizer: str,
                       architecture: str,
                       source_path: Path | None,
                       mount_path: Path | None = None,
                       no_dump: bool = False,
                       custom_script: list[str] | None = None) -> bool:
  """Build fuzzers using Docker.
    
    Args:
        local_id: Local ID for logging and output directories.
        project_dir: Path to the project directory.
        engine: Fuzzing engine to use.
        sanitizer: Sanitizer to use.
        architecture: Target architecture.
        source_path: Path to source code.
        mount_path: Mount path for source code in container.
        no_dump: Whether to suppress log output.
        custom_script: Additional custom script commands.
        
    Returns:
        True if build succeeded, False otherwise.
    """
  if custom_script is None:
    custom_script = []

  # Set the LogFile
  log_file = OSS_ERR / f"{local_id}_Image.log"
  logging.info(f"Check the output in file: {log_file}")

  # Clean The WORK/OUT DIR
  project_out = OSS_OUT / f"{local_id}_OUT"
  project_work = OSS_WORK / f"{local_id}_WORK"

  if project_out.exists():
    check_call(["sudo", "rm", "-rf", str(project_out)])
  if project_work.exists():
    check_call(["sudo", "rm", "-rf", str(project_work)])

  project_out.mkdir()
  project_work.mkdir()

  args = [
      '-t', f'gcr.io/oss-fuzz/{local_id}', '--file',
      str(project_dir / "Dockerfile"),
      str(project_dir)
  ]

  if not docker_build(args, log_file=log_file):
    logging.error(f"Failed to build DockerImage")
    return False

  # Build Succeed, Try Compiling
  if log_file and log_file.exists():
    os.remove(str(log_file))

  env = [
      'FUZZING_ENGINE=' + engine,
      'SANITIZER=' + sanitizer,
      'ARCHITECTURE=' + architecture,
      'FUZZING_LANGUAGE=' + str(get_language(project_dir)),
  ]

  command = sum([['-e', x] for x in env], [])

  # Mount the Source/Dependencies (we try to replace this with
  # modifying dockerfile)
  if source_path and mount_path:
    for item in source_path.iterdir():
      command += ['-v', f'{item}:{mount_path / item.name}']

  # Mount out/work dir
  command += [
      '-v', f'{project_out}:/out', '-v', f'{project_work}:/work', '-t',
      f'gcr.io/oss-fuzz/{local_id}'
  ]

  # supports for submodule tracker
  command += custom_script

  if not no_dump:
    log_file = OSS_ERR / f"{local_id}_Compile.log"
    logging.info(f"Check the output in file: {str(log_file)}")
  else:
    log_file = None

  result = docker_run(command, log_file=log_file)
  if not result:
    logging.error('Failed to Build Targets')
    return False
  else:
    if log_file and log_file.exists() and str(log_file) != "/dev/null":
      os.remove(str(log_file))

  logging.info(f"OUT: {project_out}")
  return True


def build_fuzzer_with_source(local_id: int | str, project_name: str,
                             srcmap: str | Path, sanitizer: str, engine: str,
                             arch: str, commit_date: datetime,
                             issue: dict[str, Any], tag: str) -> bool:
  """Build fuzzer with source code from srcmap.
    
    Args:
        local_id: Local ID for the build.
        project_name: Name of the project.
        srcmap: Path to the srcmap file.
        sanitizer: Sanitizer to use.
        engine: Fuzzing engine.
        arch: Target architecture.
        commit_date: Target commit date.
        issue: Issue information.
        tag: Build tag ('fix' or 'vul').
        
    Returns:
        True if build succeeded, False otherwise.
    """
  # Build source_dir

  with open(srcmap, encoding='utf-8') as f:
    srcmap_items = json.loads(f.read())

  if ("/src" in srcmap_items and
      srcmap_items['/src']['url'] == 'https://github.com/google/oss-fuzz.git'):
    result = prepare_ossfuzz(project_name, srcmap_items['/src']['rev'])
  else:
    result = prepare_ossfuzz(project_name, commit_date)

  if not result:
    return False
  else:
    tmp_dir, project_dir = result

  dockerfile = project_dir / 'Dockerfile'
  logging.info(f"dockerfile: {dockerfile}")

  build_data = BuildData(sanitizer=sanitizer,
                         architecture=arch,
                         engine=engine,
                         project_name=project_name)

  # Step ZERO: Rebase Dockerfiles
  if not rebase_dockerfile(dockerfile, str(commit_date).replace(" ", "-")):
    logging.error(
        f"build_fuzzer_with_source: Failed to Rebase Dockerfile, {local_id}")
    return leave_ret(False, tmp_dir)

  # Step ONE: Fix Dockerfiles
  if not fix_dockerfile(dockerfile, project_name, commit_date):
    logging.error(
        f"build_fuzzer_with_source: Failed to Fix Dockerfile, {local_id}")
    return leave_ret(False, tmp_dir)

  # Step TWO: Prepare Dependencies
  with open(srcmap, encoding='utf-8') as f:
    data = json.loads(f.read())

  source_dir = Path(tempfile.mkdtemp())
  src = source_dir / "src"
  src.mkdir(parents=True, exist_ok=True)
  docker_volume = []
  unsorted = list(data.keys())
  sorted_keys = sorted(unsorted, key=len)
  main_component = get_project_name(issue, srcmap)

  if main_component is False:
    return leave_ret(False, tmp_dir)

  force_no_err_dump = "/src/xz" in sorted_keys

  # Handle Srcmap Info
  for item_key in sorted_keys:
    # logging.info(f"Prepare Dependency: {x}")
    if skip_component(project_name, item_key):
      continue

    if tag == 'fix' and main_component == item_key:
      approximate = '+'
    else:
      approximate = '-'

    new_data = {}
    new_data['rev'] = data[item_key]['rev']
    new_key, new_data['url'], new_data['type'] = update_resource_info(
        item_key, data[item_key]['url'], data[item_key]['type'])

    del data[item_key]
    data[new_key] = new_data

    item_name = new_key
    item_url = data[new_key]['url']
    item_type = data[new_key]['type']
    item_rev = data[new_key]['rev']
    item_name = "/".join(item_name.split("/")[2:])

    if special_component(project_name, new_key, data[new_key], dockerfile):
      continue

    if (item_name == 'aflplusplus' and
        item_url == 'https://github.com/AFLplusplus/AFLplusplus.git'):
      continue

    if (item_name == 'libfuzzer' and
        'llvm.org/svn/llvm-project/compiler-rt/trunk/lib/fuzzer' in item_url):
      continue

    # Broken Revision
    if item_rev == "" or item_rev == "UNKNOWN":
      logging.error(f"Broken Meta: No Revision Provided")
      return leave_ret(False, [tmp_dir, source_dir])

    # Ignore not named dependencies if it's not main
    if item_name.strip(" ") == "" and len(data.keys()) == 1:
      logging.error(f"Broken Meta: Found Not Named Dep")
      return leave_ret(False, [tmp_dir, source_dir])

    # Broken type
    if item_type not in ['git', 'svn', 'hg']:
      logging.error(f"Broken Meta: No support for {item_type}")
      return leave_ret(False, [tmp_dir, source_dir])

    # Try to perform checkout in dockerfile,
    # which could make reproducing more reliable
    if update_revision_info(dockerfile, new_key, data[new_key], commit_date,
                            approximate):
      continue

    # Prepare the dependencies and record them. We'll use -v to mount them
    # to the docker container
    if item_type == 'git':
      clone_result = clone(item_url,
                           item_rev,
                           src,
                           item_name,
                           commit_date=commit_date)

      if clone_result is False:
        logging.error(f"[!] build_from_srcmap: Failed to clone & checkout "
                      f"[{local_id}]: {item_name}")
        return leave_ret(False, [tmp_dir, source_dir])
      elif clone_result is None:
        command = (f'git log --before="{commit_date.isoformat()}" '
                   f'-n 1 --format="%H"')
        result = subprocess.run(command,
                                stdout=subprocess.PIPE,
                                text=True,
                                shell=True,
                                cwd=src / item_name)
        commit_hash = result.stdout.strip()
        if not check_call(['git', "reset", '--hard', commit_hash],
                          cwd=src / item_name):
          logging.error(f"[!] build_from_srcmap: Failed to clone & checkout "
                        f"[{local_id}]: {item_name}")
          return leave_ret(False, [tmp_dir, source_dir])

      docker_volume.append(new_key)

    elif item_type == 'svn':
      if not svn_clone(item_url, item_rev, src, item_name):
        logging.error(
            f"[!] build_from_srcmap/svn: Failed clone & checkout: {item_name}")
        return leave_ret(False, [tmp_dir, source_dir])
      docker_volume.append(new_key)

    elif item_type == 'hg':
      if not hg_clone(item_url, item_rev, src, item_name):
        logging.error(
            f"[!] build_from_srcmap/hg: Failed clone & checkout: {item_name}")
        return leave_ret(False, [tmp_dir, source_dir])
      docker_volume.append(new_key)
    else:
      logging.error(f"Failed to support {item_type}")
      exit(1)

  # Step Three: Extra Scripts
  if not extra_scripts(project_name, source_dir):
    logging.error(f"Failed to Run ExtraScripts, {local_id}")
    return leave_ret(False, [tmp_dir, source_dir])

  if not fix_build_script(project_dir / "build.sh", project_name):
    logging.error(f"Failed to Fix Build.sh, {local_id}")
    return leave_ret(False, [tmp_dir, source_dir])

  # Let's Build It
  result = build_fuzzers_impl(local_id,
                              project_dir=project_dir,
                              engine=build_data.engine,
                              sanitizer=build_data.sanitizer,
                              architecture=build_data.architecture,
                              source_path=source_dir / "src",
                              mount_path=Path("/src"),
                              no_dump=force_no_err_dump)

  # we need sudo since the docker container root touched the folder
  check_call(["sudo", "rm", "-rf", str(source_dir)])
  return leave_ret(result, tmp_dir)


def build_from_srcmap(srcmap: Path, issue: dict[str, Any], tag: str) -> bool:
  """Build fuzzer from srcmap file.
    
    Args:
        srcmap: Path to the srcmap file.
        issue: Issue dictionary.
        tag: Build tag ('fix' or 'vul').
        
    Returns:
        True if build succeeded, False otherwise.
    """
  # Get Basic Information
  fuzzer_info = issue['job_type'].split("_")
  engine = fuzzer_info[0]
  sanitizer = get_sanitizer(fuzzer_info[1])
  arch = 'i386' if fuzzer_info[2] == 'i386' else 'x86_64'

  # Get Issue Date
  issue_date = srcmap.name.split(".")[0].split("-")[-1]
  commit_date = datetime.strptime(issue_date + " +0000", '%Y%m%d%H%M %z')

  if 'issue' not in issue:
    issue['issue'] = {'localId': issue['localId']}

  if engine not in ['libfuzzer', 'afl', 'honggfuzz', 'centipede']:
    logging.error("Failed to get engine")
    return False

  if sanitizer is False:
    logging.error("Failed to get Sanitizer")
    return False

  return build_fuzzer_with_source(issue['issue']['localId'], issue['project'],
                                  srcmap, sanitizer, engine, arch, commit_date,
                                  issue, tag)


def arvo_reproducer(local_id: int | str, tag: str) -> bool:
  """Main ARVO reproducer function.
    
    Args:
        local_id: Local ID of the vulnerability.
        tag: Version tag ('fix' or 'vul').
        
    Returns:
        True if reproduction succeeded, False otherwise.
    """
  logging.info(f"Working on {local_id}")

  # 1. Fetch the basic info for the vulnerability
  issue = fetch_issue(local_id)  # TODO, refactor a fast way
  if not issue:
    logging.error(f"Failed to get the srcmap or issue for {local_id}")
    return False

  tmpdir = Path(tempfile.mkdtemp())
  srcmap_url = issue['regressed'] if tag == 'vul' else issue['verified_fixed']
  srcmap_files = download_build_artifacts(issue, srcmap_url, tmpdir)

  if not srcmap_files:
    logging.error(f"Failed to get the srcmap for {local_id}")
    return False

  srcmap = Path(srcmap_files[0])

  # Early issues don't have 'project' field. Set project for issues that
  # didn't have it.
  if 'project' not in issue:
    issue['project'] = issue['fuzzer'].split("_")[1]

  # 2. Download the PoC
  logging.info("Downloading PoC")
  case_dir = Path(tempfile.mkdtemp())

  try:
    case_path = download_poc(issue, case_dir, "crash_case")
  except Exception:
    logging.error(f"Failed to Download the Reproducer")
    return False

  logging.info(f"POC: {case_path}")
  if not case_path or not case_path.exists():
    logging.error(f"Failed to Download the Reproducer")
    return False

  # 3. Build the Vulnerable Software
  logging.info("Building the Binary")
  result = build_from_srcmap(srcmap, issue, tag)

  if not result:
    logging.error(f"Failed to build old fuzzers from srcmap")
    return False

  return True


def main() -> None:
  """Main function."""
  parser = argparse.ArgumentParser(description='Reproduce ')
  parser.add_argument('--issueId',
                      help='The issueId of the found vulnerability '
                      'https://issues.oss-fuzz.com/',
                      required=True)
  parser.add_argument('--version',
                      default='fix',
                      help="The fixed version or vulnerable version")
  args = parser.parse_args()

  # In this script, localId == issueId
  arvo_reproducer(args.issueId, args.version)


if __name__ == "__main__":
  main()
