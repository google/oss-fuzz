import atheris
import json
import os
from unittest import mock
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'cifuzz'))

for _ in range(10):
  print(sys.path)

import pdb; pdb.set_trace()


with atheris.instrument_imports():
  import get_coverage

REPO_PATH = '/src/curl'
PROJECT_NAME = 'curl'
oss_fuzz_coverage = cifuzz.get_coverage.OSSFuzzCoverage(
    REPO_PATH, PROJECT_NAME)

def TestOneInput(data):
  try:
    decoded_json = json.loads(data)
  except (json.decoder.JSONDecodeError, UnicodeDecodeError):
    # Wart
    return oss_fuzz_coverage.get_files_covered_by_target(
          'fuzz-target')

  with mock.patch('cifuzz.get_coverage.OSSFuzzCoverage.get_target_coverage',
                  return_value=decoded_json):
    oss_fuzz_coverage.get_files_covered_by_target(
          'fuzz-target')
  return 0


def main():
  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()


if __name__ == '__main__':
  main()
