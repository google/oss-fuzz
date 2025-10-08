"""Test module for ARVO reproducer functionality.

This module contains functional tests for the ARVO reproducer components:
1. The functionality of reproducer components.
2. The building of a project's fuzzers from a vulnerability found on OSS-Fuzz.
"""

import shutil
import tempfile
import unittest
import warnings
from datetime import datetime
from pathlib import Path
from typing import Dict, Any

from arvo_reproducer import (arvo_reproducer, download_poc, fetch_issue,
                             prepare_ossfuzz, rebase_dockerfile)
from arvo_utils import execute

# Suppress Google auth warnings
warnings.filterwarnings("ignore",
                        category=UserWarning,
                        module="google.auth._default")

# Test constants
REPRODUCE_TEST_LOCAL_ID = 42487096
UNITTEST_LOCAL_ID = 42498388


class ArvoReproducingTest(unittest.TestCase):
  """Test class for ARVO reproducer functionality."""

  def test_reproduce(self) -> None:
    """Test the complete reproduction process."""
    result = arvo_reproducer(REPRODUCE_TEST_LOCAL_ID, 'vul')
    self.assertEqual(result, True)

    case_dir = Path(tempfile.mkdtemp())
    issue = fetch_issue(REPRODUCE_TEST_LOCAL_ID)  # TODO, refactor a fast way
    download_poc(issue, case_dir, "crash_case")

    (case_dir / "stderr").touch()
    with open(case_dir / "stderr", 'wb') as f:
      execute([
          f'/tmp/{REPRODUCE_TEST_LOCAL_ID}_OUT/set_eval_fuzzer',
          str(case_dir / "crash_case")
      ],
              stdout=f,
              stderr=f)

    with open(case_dir / "stderr", 'rb') as f:
      crash_info = f.read()

    self.assertEqual(
        b"SUMMARY: AddressSanitizer: heap-buffer-overflow " in crash_info, True)

    shutil.rmtree(case_dir)


class ArvoUnitTests(unittest.TestCase):
  """Unit tests for individual ARVO reproducer components."""

  def test_fetch_issue(self) -> None:
    """Test if we can get issues from OSS-Fuzz."""
    expected_issue_cve_2021_38593: Dict[str, Any] = {
        'project':
            'qt',
        'job_type':
            'libfuzzer_asan_i386_qt',
        'platform':
            'linux',
        'crash_type':
            'UNKNOWN WRITE',
        'crash_address':
            '0x10000000',
        'severity':
            'High',
        'regressed':
            'https://oss-fuzz.com/revisions?job=libfuzzer_asan_i386_qt&'
            'range=202106240616:202106250624',
        'reproducer':
            'https://oss-fuzz.com/download?testcase_id=6379642528333824',
        'verified_fixed':
            'https://oss-fuzz.com/revisions?job=libfuzzer_asan_i386_qt&'
            'range=202107280604:202107290609',
        'localId':
            42498388,
        'sanitizer':
            'address',
        'fuzz_target':
            'qtsvg_svg_qsvgrenderer_render'
    }

    issue = fetch_issue(UNITTEST_LOCAL_ID)
    self.assertEqual(expected_issue_cve_2021_38593, issue)

  def test_download_poc(self) -> None:
    """Test if we can download proof-of-concept files."""
    issue = fetch_issue(UNITTEST_LOCAL_ID)
    case_dir = Path(tempfile.mkdtemp())

    result = download_poc(issue, case_dir, "crash_case")
    self.assertEqual(result.name, "crash_case")

    shutil.rmtree(case_dir)

  def test_rebase_dockerfile(self) -> None:
    """Test if we can get the historical dockerfile and rebase it."""
    commit_date = datetime.strptime("202409200607" + " +0000", '%Y%m%d%H%M %z')
    result = prepare_ossfuzz("libxml2", commit_date)

    commit_date_str = str(commit_date).replace(" ", "-")
    rebase_result = rebase_dockerfile(result[1] / "Dockerfile", commit_date_str)

    self.assertEqual(rebase_result, True)
    shutil.rmtree(result[0])


if __name__ == '__main__':
  unittest.main()
