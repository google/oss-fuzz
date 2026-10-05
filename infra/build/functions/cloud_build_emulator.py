#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys
import subprocess
import tempfile
import urllib.request


def run_commands(steps, workspace):
  os.chdir(workspace)  # Needed for compatibility.
  for command in json.loads(steps)['steps']:
    docker_command = [
      'docker', 'run', '-v', f'{workspace}:/workspace:rw', '-v', 
      '/var/run/docker.sock:/var/run/docker.sock:rw',
    ]
    for env_var in command.get('env', []):
      docker_command.extend(['-e', env_var])

    entrypoint = command.get('entrypoint')
    if entrypoint:
      docker_command += ['--entrypoint', f'{Path(entrypoint).resolve()}']
    
    args = command.get('args', []) # Ignore this for now as it causes errors.
    # !!! It's hacky that I'm doing abspath this but it seems to be needed.  
    args = [arg for arg in args if not arg.startswith('--network')]
    directory = os.path.abspath(command.get('dir', '/workspace'))
    docker_command += ['-w', directory, command['name']] + args

    print(f'Running command:', docker_command)
    docker_command = ['sudo'] + docker_command
    subprocess.run(docker_command, check=True)

def main():
  url = os.getenv('INPUT_DOWNLOAD_URL')
  with urllib.request.urlopen(url) as response:
    content = response.read().decode()
  os.system('sudo mkdir /workspace')
  run_commands(content, '/workspace')

# def main():
#   with open(sys.argv[1], 'r') as f:
#     commands = yaml.safe_load(f)
#   # !!! FIX  
#   run_commands(commands, '/workspace')

if __name__ == '__main__':
  main()
