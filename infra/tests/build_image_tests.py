"""Unit tests for helper.py  build_image function using a specific commit.

This unit test calls the build_image --commit command which attempts
to create a docker image using a specific commit SHA. It then creates
a container of the created image and checks to see what commit the container is at.
If the commit set and the container commit match up, then the test passes.

  Typical usage example:

  python build_image_test.py
"""

# Add helper.py to the python path
import sys
sys.path.append("..")

import unittest
import os
import subprocess

from helper import _build_image_from_commit
from helper import _is_base_image

# List of test cases to use for the
TEST_DATA_FILE = "build_image_tests_commit.data"

# The pairs of project names to commits that are to be tested
test_data = dict()


class TestBuildImageCommit(unittest.TestCase):
    """Tests that a docker image can be build with a specific commit."""


    def test_project_build_to_commit(self):

        for project_name, commit_id in test_data.items():

            # switch dirs for build_image call to run properly
            cur_dir = os.getcwd()
            os.chdir("../..")
            _build_image_from_commit(project_name, commit_id)
            os.chdir(cur_dir)
            is_base_image = _is_base_image(project_name)
            if is_base_image:
                image_project = 'oss-fuzz-base'
            else:
                image_project = 'oss-fuzz'

            # Extracting git version from the built docker image
            image_location = "gcr.io/%s/%s" % (image_project, project_name)
            bash_command = "cd /src/%s ; git rev-parse HEAD" % project_name
            command = [
                'docker', 'run', '-i', '--privileged', image_location, 'bash',
                '-c', bash_command
            ]
            process = subprocess.Popen(command, stdout=subprocess.PIPE)
            out, err = process.communicate()
            image_commit = out.decode('ascii').strip('\n')
            self.assertEqual(image_commit, commit_id)


def load_test_data():
    """ Loads the project names and commit IDs into a dictionary"""

    with open(TEST_DATA_FILE) as data_file:
        for line in data_file.readlines():
            pairs = line.strip('\n').split(" ")
            test_data[pairs[0]] = pairs[1]


if __name__ == '__main__':
    load_test_data()
    unittest.main()

