""" Unit tests for helper.py  build_image function.
    Testing the functionality of building the image of
    a specific commit rather than just the most recent one"""

import unittest
import os
import sys
import subprocess
sys.path.append("..")
from helper import _build_image
from helper import _is_base_image

# List of test cases to use for the
TEST_DATA_FILE = "build_image_tests_commit.data"

# The pairs of project names to commits that are to be tested
test_data = dict()


class TestBuildImageCommit(unittest.TestCase):
    """ Tests the functionality of building a docker image to a
      commit rather than head
  """

    def test_project_build_to_commit(self):
        """ Tests if a project's image is build to a specific commit"""

        for project_name, commit_id in test_data.items():

            # needs to switch dirs for build_image to work
            cur_dir = os.getcwd()
            os.chdir("../..")
            _build_image(project_name, commit=commit_id)
            os.chdir(cur_dir)

            # Get correct docker image name
            is_base_image = _is_base_image(project_name)
            if is_base_image:
                image_project = 'oss-fuzz-base'
            else:
                image_project = 'oss-fuzz'

            # get the git version from the docker image
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

