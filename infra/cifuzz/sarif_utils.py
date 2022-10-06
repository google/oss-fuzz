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
"""Module for outputting SARIF data."""
import base64
import gzip
import io
import json
import os

import requests

CFL_VERSION = '1'
SARIF_SCHEMA_VERSION = '2.1.0'
NO_CRASHES_NAME = 'NoCrashes'
NO_CRASHES_ID = f'{NO_CRASHES_NAME}ID'


def format_sarif_for_github(sarif_dict):
  sarif_str = json.dumps(sarif_dict)
  result = io.StringIO()
  with gzip.GzipFile(fileobj=result, mode='w') as gzip_file:
    gzip_file.write(sarif_str)
  return result.getvalue()


def http_upload_sarif_dict(sarif_dict):
  sarif_data = format_sarif_for_github(sarif_dict)


def write_sarif_for_upload(cfl_result, config):
  sarif_dict = get_sarif_data(cfl_result)
  filename = os.path.join(config.project_src_path, 'results.sarif')
  with open(filename, 'w') as file_handle:
    file_handle.write(json.dumps(sarif_dict))


def get_sarif_data(cfl_result):
  start_line = end_line = 5
  snippet_text = 'if (bad) {BUG();}'
  src_file = 'src/file1.cpp'
  run = {
      'tool': {
          'driver': {
              'name':
                  'ClusterFuzzLite',
              'version':
                  CFL_VERSION,
              'informationUri':
                  'https://google.github.io/clusterfuzzlite/',
              'rules': [{
                  'id': NO_CRASHES_ID,
                  'name': NO_CRASHES_NAME,
                  'helpUri': 'https://google.github.io/clusterfuzzlite',
                  'shortDescription': {
                      'text': NO_CRASHES_NAME
                  },
                  'fullDescription': {
                      'text': NO_CRASHES_NAME
                  },
                  'help': {
                      'text':
                          'Don\'t crash',
                      'markdown':
                          '**Remediation (click \'Show more\' below)**:\n\n- not-used1\n\n- not-used2\n\n\n\n**Severity**: High\n\n\n\n**Details**:\n\nlong description\n\n other line'
                  },
                  'defaultConfiguration': {
                      'level': 'error'
                  },
                  'properties': {
                      'precision': 'high',
                      'problem.severity': 'error',
                      'security-severity': '7.0',
                      'tags': ['tag1', 'tag2']
                  }
              }]
          },
      },
      'results': [{
          'ruleId':
              NO_CRASHES_ID,
          'ruleIndex':
              0,
          'message': {
              'text':
                  'score is 5: warn message\nClick Remediation section below to solve this issue'
          },
          'locations': [{
              'physicalLocation': {
                  'region': {
                      'startLine': start_line,
                      'endLine': end_line,
                      'snippet': {
                          'text': snippet_text
                      }
                  },
                  'artifactLocation': {
                      'uri': src_file,
                      'uriBaseId': '%SRCROOT%'
                  }
              },
              'message': {
                  'text': 'warn message'
              }
          }]
      }]
  }
  sarif = {
      '$schema': ('https://raw.githubusercontent.com/oasis-tcs/sarif-spec/'
                  'master/Schemata/sarif-schema-2.1.0.json'),
      'version': SARIF_SCHEMA_VERSION,
      'runs': [run]
  }

  return json.dumps(sarif, indent=4)
