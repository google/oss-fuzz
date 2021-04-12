# Copyright 2021 Google LLC
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
"""Tests the functionality of the fuzz_target module."""

import subprocess
import unittest
from unittest.mock import call
from unittest import mock

from pyfakefs import fake_filesystem_unittest

import docker

# pylint: disable=no-self-use,too-few-public-methods,protected-access


class TestGetProjectImageName(unittest.TestCase):
  """Tests for get_project_image_name."""

  def test_get_project_image_name(self):
    """Tests that get_project_image_name works as intended."""
    project_name = 'myproject'
    result = docker.get_project_image_name(project_name)
    self.assertEqual(result, 'gcr.io/oss-fuzz/myproject')


class TestDeleteImages(unittest.TestCase):
  """Tests for get_project_image_name."""

  @mock.patch('utils.execute')
  def test_delete_images(self, mocked_execute):
    """Tests thart delete_images deletes images."""
    images = ['myimage1', 'myimage2']
    docker.delete_images(images)
    mocked_execute.assert_has_calls([
        call(['docker', 'rmi', '-f'] + images),
        call(['docker', 'builder', 'prune', '-f'])
    ])


class TestStopDockerContainer(unittest.TestCase):
  """Tests for stop_docker_container."""

  @mock.patch('subprocess.run', return_value=mock.MagicMock(returncode=0))
  def test_stop_docker_container(self, mocked_run):
    """Tests that stop_docker_container works as intended."""
    container_id = 'container-id'
    wait_time = 100
    result = docker.stop_docker_container(container_id, wait_time)
    mocked_run.assert_called_with(
        ['docker', 'stop', container_id, '-t',
         str(wait_time)], check=False)
    self.assertTrue(result)


class TestHandleTimedOutContainerProcess(fake_filesystem_unittest.TestCase):
  """Tests for _handle_timed_out_container_process."""
  ERROR_EXPECTED_RESULT = (None, None)
  CONTAINER_ID = 'container-id'
  CID_FILENAME = '/cid-file'

  def setUp(self):
    self.setUpPyfakefs()
    self.fs.create_file(self.CID_FILENAME, contents=self.CONTAINER_ID)

  @mock.patch('logging.error')
  def test_unreadable_file(self, mocked_error):
    """Tests that _handle_timed_out_container_process doesn't exception when the
    cidfile doesn't exist."""
    fake_cid_file = '/tmp/my-fake/cid-file'
    result = docker._handle_timed_out_container_process(mock.MagicMock(),
                                                        fake_cid_file)
    self.assertEqual(result, self.ERROR_EXPECTED_RESULT)
    mocked_error.assert_called_with('cid_file not found.')

  @mock.patch('logging.error')
  @mock.patch('docker.stop_docker_container')
  def test_stop_docker_container_failed(self, mocked_stop_docker_container,
                                        mocked_error):
    """Tests that _handle_timed_out_container_process behaves properly when it
    fails to stop the docker container."""
    mocked_stop_docker_container.return_value = False

    result = docker._handle_timed_out_container_process(mock.MagicMock(),
                                                        self.CID_FILENAME)

    mocked_stop_docker_container.assert_called_with(self.CONTAINER_ID)
    self.assertEqual(result, self.ERROR_EXPECTED_RESULT)
    mocked_error.assert_called_with('Failed to stop docker container: %s',
                                    self.CONTAINER_ID)

  @mock.patch('logging.error')
  @mock.patch('docker.stop_docker_container')
  def test_handle_timed_out_container_process(self,
                                              mocked_stop_docker_container,
                                              mocked_error):
    """Tests that test_handle_timed_out_container_process works as intended."""
    mocked_stop_docker_container.return_value = True
    process = mock.MagicMock()
    process.communicate = lambda *args, **kwargs: None
    result = docker._handle_timed_out_container_process(process,
                                                        self.CID_FILENAME)

    # communicate returns None because of the way we mocked Popen.
    self.assertIsNone(result)

    mocked_error.assert_not_called()


class TestRunContainerCommand(unittest.TestCase):
  """Tests for run_container_command."""
  ARGUMENTS = ['argument']

  @mock.patch('docker._handle_timed_out_container_process',
              return_value=(None, None))
  @mock.patch('logging.warning')
  @mock.patch('subprocess.Popen')
  def test_timeout(self, mocked_popen, mocked_warning, _):
    """Tests run_container_command behaves as expected when the command times
    out."""
    popen_magic_mock = mock.MagicMock()
    mocked_popen.return_value = popen_magic_mock
    popen_magic_mock.communicate.side_effect = subprocess.TimeoutExpired(
        ['cmd'], '1')
    result = docker.run_container_command(self.ARGUMENTS)
    self.assertEqual(mocked_warning.call_count, 1)
    self.assertTrue(result.timed_out)

  @mock.patch('docker._handle_timed_out_container_process')
  @mock.patch('subprocess.Popen')
  def test_run_container_command(self, mocked_popen,
                                 mocked_handle_timed_out_container_process):
    """Tests run_container_command behaves as expected."""
    popen_magic_mock = mock.MagicMock()
    mocked_popen.return_value = popen_magic_mock
    popen_magic_mock.communicate.return_value = (None, None)
    mocked_handle_timed_out_container_process.return_value = (None, None)
    result = docker.run_container_command(self.ARGUMENTS)
    mocked_handle_timed_out_container_process.assert_not_called()
    self.assertFalse(result.timed_out)
