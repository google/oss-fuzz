#!/usr/bin/env python3
# Copyright 2025 Google LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""index_build tests.

This is only runnable on OSS-Fuzz infrastructure.
"""

import json
import os
import pathlib
import subprocess
import tarfile
from typing import Sequence
import unittest

import manifest_types

THIS_DIR = pathlib.Path(__file__).parent
OSS_FUZZ_DIR = THIS_DIR.parent.parent.parent.parent


@unittest.skipUnless(
    os.getenv('INDEX_BUILD_TESTS'), 'Tests do not run on infra'
)
class IndexBuildTest(unittest.TestCase):

  def _build_project(
      self, project: str, *additional_args, compressed: bool
  ) -> Sequence[pathlib.Path]:
    subprocess.run(
        ('python3', 'infra/helper.py', 'build_image', '--no-pull', project),
        cwd=OSS_FUZZ_DIR,
        check=True,
    )

    out_dir = OSS_FUZZ_DIR / f'build/out/{project}'
    docker_args = [
        'docker',
        'run',
        '--rm',
        '-e',
        f'PROJECT_NAME={project}',
        '-v',
        f'{THIS_DIR}:/opt/indexer',
        '-v',
        f'{out_dir}:/out',
        f'gcr.io/oss-fuzz/{project}',
        '/opt/indexer/index_build.py',
    ]

    if additional_args:
      docker_args.extend(additional_args)

    file_suffix = '.tar'
    if compressed:
      docker_args.append('--compressed')
      file_suffix = '.tgz'

    subprocess.run(docker_args, cwd=OSS_FUZZ_DIR, check=True)
    return [
        file
        for file in out_dir.iterdir()
        if file.suffix == file_suffix and file.name.startswith(project)
    ]

  def _check_archive(self, archive_path: pathlib.Path):
    has_obj_lib = False
    has_idx_sqlite = False
    has_idx_absolute = False
    has_idx_relative = False
    manifest = None
    print(f'Testing {archive_path}')
    with tarfile.open(archive_path) as tar:
      members = tar.getmembers()
      for member in members:
        if member.name.startswith('obj/lib/'):
          has_obj_lib = True
        if member.name.startswith('idx/absolute/'):
          has_idx_absolute = True
        if member.name.startswith('idx/relative/'):
          has_idx_relative = True
        if member.name == 'idx/db.sqlite':
          has_idx_sqlite = True
        if member.name == 'manifest.json':
          file = tar.extractfile(member)
          self.assertIsNotNone(file)
          if file:  # Make type checkers happy.
            manifest = json.load(file)
            self.assertTrue(manifest['lib_mount_path'])
            self.assertIsNotNone(
                tar.getmember('obj/' + manifest['binary_config']['binary_name'])
            )
            self.assertEqual(
                manifest['binary_config']['binary_args'],
                [manifest_types.INPUT_FILE],
            )

    self.assertTrue(has_obj_lib, 'obj/lib/ was not found in the archive.')
    self.assertTrue(
        has_idx_sqlite, 'idx/db.sqlite was not found in the archive.'
    )
    self.assertTrue(
        has_idx_absolute, 'idx/absolute/ was not found in the archive.'
    )
    self.assertTrue(
        has_idx_relative, 'idx/relative/ was not found in the archive.'
    )
    self.assertIsNotNone(
        manifest, 'manifest.json was not found or is empty in the archive.'
    )

  def test_basic_build(self):
    """Test basic build."""
    for compressed in (False, True):
      archives = self._build_project('expat', compressed=compressed)
      self.assertGreater(len(archives), 0)
      for archive in archives:
        self._check_archive(archive)

  def test_build_with_target_allowlist(self):
    """Test basic build with target allowlist."""
    for compressed in (False, True):
      archives = self._build_project(
          'expat',
          '--targets',
          'xml_parse_fuzzer_UTF-8',
          compressed=compressed,
      )
      self.assertEqual(len(archives), 1)
      self.assertIn('xml_parse_fuzzer_UTF-8', archives[0].name)
      for archive in archives:
        self._check_archive(archive)
