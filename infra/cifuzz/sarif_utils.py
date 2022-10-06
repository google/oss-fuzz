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
import json

CFL_VERSION = '1'

def get_sarif_data(cfl_result):
  run = {
      'tool': {
          'driver': {
          'name': 'ClusterFuzzLite',
          'version': CFL_VERSION,
          'informationUri': 'https://google.github.io/clusterfuzzlite/',
          'rules': [
                  {
                     "id": "NoCrashesID",
                     "name": "NoCrashes",
                     "helpUri": "https://google.github.io/clusterfuzzlite",
                     "shortDescription": {
                        "text": "NoCrashes"
                     },
                     "fullDescription": {
                        "text": "NoCrashes"
                     },
                     "help": {
                        "text": "Don\'t crash",
                        "markdown": "**Remediation (click \"Show more\" below)**:\n\n- not-used1\n\n- not-used2\n\n\n\n**Severity**: High\n\n\n\n**Details**:\n\nlong description\n\n other line"
                     },
                     "defaultConfiguration": {
                        "level": "error"
                     },
                     "properties": {
                        "precision": "high",
                        "problem.severity": "error",
                        "security-severity": "7.0",
                        "tags": [
                           "tag1",
                           "tag2"
                        ]
                     }
                  }
          ]
      },
      # 'artifacts': [
      #         {
      #             'location': {
      #                 'uri': 'file:///C:/dev/sarif/sarif-tutorials/samples/Introduction/simple-example.js'
      #             }
      #         }
      # ],
      },

      "results": [
            {
               "ruleId": "CheckNameID",
               "ruleIndex": 0,
               "message": {
                  "text": "score is 5: warn message\nClick Remediation section below to solve this issue"
               },
               "locations": [
                  {
                     "physicalLocation": {
                        "region": {
                           "startLine": 5,
                           "endLine": 5,
                           "snippet": {
                              "text": "if (bad) {BUG();}"
                           }
                        },
                        "artifactLocation": {
                           "uri": "src/file1.cpp",
                           "uriBaseId": "%SRCROOT%"
                        }
                     },
                     "message": {
                        "text": "warn message"
                     }
                  }
               ]
            }
         ]
  }
  sarif = {
      '$schema': ('https://raw.githubusercontent.com/oasis-tcs/sarif-spec/'
                  'master/Schemata/sarif-schema-2.1.0.json'),
      'version': '2.1.0', # !!! Delete?
      'runs': [run]
  }

  return json.dumps(sarif, indent=4)
