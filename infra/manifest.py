import logging
import subprocess
import sys

def push_manifest(image):
  subprocess.run(['docker', 'pull', image], check=True)
  amd64_image = f'{image}:manifest-amd64'
  subprocess.run(['docker', 'tag', image, amd64_image],
                 check=True)
  subprocess.run(['docker', 'push', amd64_image], check=True)

  arm_version = f'{image}-testing-arm'
  subprocess.run(['docker', 'pull', arm_version], check=True)
  arm64_image = f'{image}:manifest-arm64v8'
  subprocess.run(['docker', 'tag', arm_version, arm64_image],
                 check=True)

  subprocess.run(['docker', 'manifest', 'create', image, '--amend', arm64_image,
                  '--amend', amd64_image])
  subprocess.run(['docker', 'manifest', 'push', image])
  return True


def main():
  logging.info('Doing simple gcloud command to ensure 2FA passes. '
               'Otherwise docker push fails.')
  subprocess.run(['gcloud', 'projects', 'list', '--limit=1'], check=True)

  images = [
      'gcr.io/oss-fuzz-base/base-builder', 'gcr.io/oss-fuzz-base/base-runner']
  results = [push_manifest(image) for image in images]
  return 0 if all(results) else 1

if __name__ == '__main__':
  sys.exit(main())
