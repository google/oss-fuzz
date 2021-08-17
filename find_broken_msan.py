import csv
import os
import multiprocessing
import subprocess
import tempfile
import zipfile


OSS_FUZZ_DIR = os.path.dirname(__file__)
PROJECTS_DIR = os.path.join(OSS_FUZZ_DIR, 'projects')
MSG_LINES = [
    '# Disabled MSAN because of https://github.com/google/oss-fuzz/issues/6180',
    '#  - memory',
]

def get_msan_projects():
  msan_projects = []
  for project in os.listdir(PROJECTS_DIR):
    project_yaml_path = os.path.join(PROJECTS_DIR, project, 'project.yaml')
    if not os.path.exists(project_yaml_path):
      continue
    with open(project_yaml_path) as fp:
      project_yaml = fp.read()
    if 'memory' in project_yaml:
      msan_projects.append(project)
  return msan_projects

def get_msan_build(project):
  result = subprocess.run(['gsutil', 'ls', f'gs://clusterfuzz-builds/{project}/{project}-memory-*.zip'], stdout=subprocess.PIPE)
  lines = result.stdout.splitlines()
  if not lines:
    return None
  return (project, lines[-1].decode())


def get_msan_builds(msan_projects, pool):
  return [build for build in pool.map(get_msan_build, msan_projects) if build]

def download_build(temp_dir, project, build):
  zip_path = os.path.join(temp_dir, f'{project}.zip')
  subprocess.run(['gsutil', 'cp', build, zip_path])
  return zip_path

def _check_build_on_disk(build_path):
  with zipfile.ZipFile(build_path) as zip_file:
    info_list = zip_file.infolist()
  for info in info_list:
    filename = info.filename.strip('/')
    if 'instrumented_libraries' == filename:
      continue
    if 'instrumented_libraries' in filename:
      return False
  return True


def check_msan_build(project_and_build):
  project, build = project_and_build
  with tempfile.TemporaryDirectory() as temp_dir:
    build_path = download_build(temp_dir, project, build)
    result = _check_build_on_disk(build_path)
    print(project, result)

    return project, result


def check_msan_builds(msan_builds, pool):
  return [result for result in pool.map(check_msan_build, msan_builds) if result]


def disable_project(project):
  project_yaml_path = os.path.join(PROJECTS_DIR, project, 'project.yaml')
  with open(project_yaml_path, 'r') as fp:
    project_yaml = fp.read()
  project_yaml_lines = project_yaml.splitlines()
  print('py', project_yaml_lines)
  for idx, line in enumerate(project_yaml_lines):
    if 'memory' in line:
      print('break')
      break
  else:
    assert False
  project_yaml_lines = project_yaml_lines[:idx] + MSG_LINES + project_yaml_lines[idx+1:]
  project_yaml = '\n'.join(project_yaml_lines)
  with open(project_yaml_path, 'w') as fp:
    fp.write(project_yaml)


def to_csv(projects, filename='broken-msan.csv'):
  with open(filename, 'w') as fp:
    writer = csv.writer(fp)
    for project, result in projects:
      writer.writerow([project, result])


def main():
  pool = multiprocessing.Pool()
  msan_projects = get_msan_projects()
  print('got projects')
  msan_builds = get_msan_builds(msan_projects, pool)
  print('got builds')
  projects = check_msan_builds(msan_builds, pool)
  return projects

if __name__ == '__main__':
  main()
