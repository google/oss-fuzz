import argparse
import logging
import os
import re
import sys
import subprocess

import functools

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
PROJECTS_DIR = os.path.join(ROOT_DIR, 'projects')

IMAGE_DIGEST_REGEX = re.compile(r'\[(.+)\]\n')
FROM_LINE_REGEX = re.compile(
    r'FROM (gcr.io\/oss-fuzz-base\/base-builder[\-a-z0-9]*)(\@?.*)')

@functools.cache
def get_latest_docker_image_digest(image):
  subprocess.run(['docker', 'pull', image], check=True)
  subprocess.run(['docker', 'pull', image], stdout=subprocess.PIPE, check=True)

  command = [
      'docker', 'image', 'inspect', '--format', '{{.RepoDigests}}', image]
  output = subprocess.run(command, check=True,
                          stdout=subprocess.PIPE).stdout.decode('utf-8')
  return IMAGE_DIGEST_REGEX.match(output).groups(1)[0]


def get_args():
  parser = argparse.ArgumentParser(sys.argv[0],
                                   description='Hold back builder images.')
  parser.add_argument('projects',
                      help='Projects. "All" for all projects',
                      nargs='+')

  parser.add_argument(
      '--hold-image-digest',
      required=False,
      nargs='?',
      default=None,
      help='Image to hold on.')

  parser.add_argument(
      '--update-held',
      action='store_true',
      default=False,
      help='Update held images.')

  parser.add_argument(
      '--issue-number',
      required=False,
      nargs='?',
      default=None,
      help='Image to hold on.')

  args = parser.parse_args()
  return args


def get_hold_image_digest(line, hold_image_digest, update_held):
  matches = FROM_LINE_REGEX.match(line).groups()
  if matches[1] and not update_held:
    return None, False
  initial_image = matches[0]
  return get_latest_docker_image_digest(initial_image), True


def hold_image(project, hold_image_digest, update_held, issue_number):
  dockerfile_path = os.path.join(PROJECTS_DIR, project, 'Dockerfile')
  with open(dockerfile_path, 'r') as dockerfile_handle:
    dockerfile = dockerfile_handle.readlines()
  for idx, line in enumerate(dockerfile[:]):
    if not line.startswith('FROM gcr.io/oss-fuzz-base/base-builder'):
      continue

    hold_image_digest, should_hold = get_hold_image_digest(
        line.strip(), hold_image_digest, update_held)
    if not should_hold:
      logging.error(f'Not holding back {project}.')
      break
    dockerfile[idx] = f'FROM {hold_image_digest}\n'
    if issue_number:
      comment = (
          '# Held back because of github.com/google/oss-fuzz/pull/'
          f'{issue_number}\n# Please fix failure and upgrade.\n')
      dockerfile.insert(idx, comment)
    break
  else:
    # This path is taken when we don't break out of the loop.
    assert None, f'Could not find FROM line in {project}'
  dockerfile = ''.join(dockerfile)
  with open(dockerfile_path, 'w') as dockerfile_handle:
    dockerfile_handle.write(dockerfile)

def main():
  args = get_args()
  for project in args.projects:
    hold_image(
        project, args.hold_image_digest, args.update_held, args.issue_number)
  return 0



if __name__ == '__main__':
  sys.exit(main())
