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
import re


# Regular expression pattern for valid schedule format (e.g., "0 0 * * *")
SCHEDULE_PATTERN = re.compile(r'^\d+\s\d+\s\d+\s\d+\s\d+$')


# pylint: disable=too-few-public-methods
class Project(ndb.Model):
    """Represents an integrated OSS-Fuzz project."""
    name = ndb.StringProperty(required=True)
    schedule = ndb.StringProperty(required=True)

    @classmethod
    def _validate_schedule(cls, prop, value):
        if not SCHEDULE_PATTERN.match(value):
            raise ValueError('Invalid schedule format')

    project_yaml_contents = ndb.TextProperty(required=True)
    dockerfile_contents = ndb.TextProperty(required=True)

    _validators = {
        'schedule': _validate_schedule
    }


# pylint: disable=too-few-public-methods
class GithubCreds(ndb.Model):
    """Represents GitHub credentials."""
    client_id = ndb.StringProperty(required=True)
    client_secret = ndb.StringProperty(required=True)


# pylint: disable=too-few-public-methods
class BuildsHistory(ndb.Model):
    """Container for build history of projects."""
    build_tag = ndb.StringProperty(required=True)
    project = ndb.StringProperty(required=True)
    build_ids = ndb.StringProperty(repeated=True)


class LastSuccessfulBuild(ndb.Model):
    """Container for storing last successful build of project."""
    build_tag = ndb.StringProperty(required=True)
    project = ndb.StringProperty(required=True)
    build_id = ndb.StringProperty(required=True)
    finish_time = ndb.StringProperty(required=True)
