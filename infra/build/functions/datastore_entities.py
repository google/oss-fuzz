# Copyright 2020 Google Inc.
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
#
################################################################################
"""Cloud datastore entity classes."""
from google.cloud import ndb


# pylint: disable=too-few-public-methods
class Project(ndb.Model):
  """Represents an integrated OSS-Fuzz project."""
  name = ndb.StringProperty()
  schedule = ndb.StringProperty()
  project_yaml_contents = ndb.TextProperty()
  dockerfile_contents = ndb.TextProperty()


# pylint: disable=too-few-public-methods
class GithubCreds(ndb.Model):
  """Represents GitHub credentials."""
  client_id = ndb.StringProperty()
  client_secret = ndb.StringProperty()


# pylint: disable=too-few-public-methods
class BuildsHistory(ndb.Model):
  """Container for build history of projects."""
  build_tag = ndb.StringProperty()
  project = ndb.StringProperty()
  build_ids = ndb.StringProperty(repeated=True)


class LastSuccessfulBuild(ndb.Model):
  """Container for storing last successful build of project."""
  build_tag = ndb.StringProperty()
  project = ndb.StringProperty()
  build_id = ndb.StringProperty()
  finish_time = ndb.StringProperty()
