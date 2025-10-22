# Copyright 2023 Google LLC
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
import copy
import json
import logging
import os

from clusterfuzz import stacktraces

SARIF_RULES = [
    {
        'id': 'no-crashes',
        'shortDescription': {
            'text': 'Don\'t crash'
        },
        'helpUri': 'https://cwe.mitre.org/data/definitions/416.html',
        'properties': {
            'category': 'Crashes'
        }
    },
    {
        'id': 'heap-use-after-free',
        'shortDescription': {
            'text': 'Use of a heap-object after it has been freed.'
        },
        'helpUri': 'https://cwe.mitre.org/data/definitions/416.html',
        'properties': {
            'category': 'Crashes'
        }
    },
    {
        'id': 'heap-buffer-overflow',
        'shortDescription': {
            'text': 'A read or write past the end of a heap buffer.'
        },
        'helpUri': 'https://cwe.mitre.org/data/definitions/122.html',
        'properties': {
            'category': 'Crashes'
        }
    },
    {
        'id': 'stack-buffer-overflow',
        'shortDescription': {
            'text': 'A read or write past the end of a stack buffer.'
        },
        'helpUri': 'https://cwe.mitre.org/data/definitions/121.html',
        'properties': {
            'category': 'Crashes'
        }
    },
    {
        'id': 'global-buffer-overflow',
        'shortDescription': {
            'text': 'A read or write past the end of a global buffer.'
        },
        'helpUri': 'https://cwe.mitre.org/data/definitions/121.html',
        'properties': {
            'category': 'Crashes'
        }
    },
    {
        'id': 'stack-use-after-return',
        'shortDescription': {
            'text':
                'A stack-based variable has been used after the function returned.'
        },
        'helpUri': 'https://cwe.mitre.org/data/definitions/562.html',
        'properties': {
            'category': 'Crashes'
        }
    },
    {
        'id': 'stack-use-after-scope',
        'shortDescription': {
            'text':
                'A stack-based variable has been used outside of the scope in which it exists.'
        },
        'helpUri': 'https://cwe.mitre.org/data/definitions/562.html',
        'properties': {
            'category': 'Crashes'
        }
    },
    {
        'id': 'initialization-order-fiasco',
        'shortDescription': {
            'text': 'Problem with order of initialization of global objects.'
        },
        'helpUri': 'https://isocpp.org/wiki/faq/ctors#static-init-order',
        'properties': {
            'category': 'Crashes'
        }
    },
    {
        'id':
            'direct-leak',
        'shortDescription': {
            'text': 'Memory is leaked.'
        },
        'helpUri':
            'https://github.com/google/sanitizers/wiki/AddressSanitizerLeakSanitizer',
        'properties': {
            'category': 'Crashes'
        }
    },
    {
        'id':
            'indirect-leak',
        'shortDescription': {
            'text': 'Memory is leaked.'
        },
        'helpUri':
            'https://github.com/google/sanitizers/wiki/AddressSanitizerLeakSanitizer',
        'properties': {
            'category': 'Crashes'
        }
    },
]
SARIF_DATA = {
    'version':
        '2.1.0',
    '$schema':
        'http://json.schemastore.org/sarif-2.1.0-rtm.4',
    'runs': [{
        'tool': {
            'driver': {
                'name': 'ClusterFuzzLite/CIFuzz',
                'informationUri': 'https://google.github.io/clusterfuzzlite/',
                'rules': SARIF_RULES,
            }
        },
        'results': []
    }]
}

SRC_ROOT = '/src/'


def redact_src_path(src_path):
  """Redact the src path so that it can be reported to users."""
  src_path = os.path.normpath(src_path)
  if src_path.startswith(SRC_ROOT):
    src_path = src_path[len(SRC_ROOT):]

  src_path = os.sep.join(src_path.split(os.sep)[1:])
  return src_path


def get_error_frame(crash_info):
  """Returns the stackframe where the error occurred."""
  if not crash_info.crash_state:
    return None
  state = crash_info.crash_state.split('\n')[0]
  logging.info('state: %s frames %s, %s', state, crash_info.frames,
               [f.function_name for f in crash_info.frames[0]])

  for crash_frames in crash_info.frames:
    for frame in crash_frames:
      # TODO(metzman): Do something less fragile here.
      if frame.function_name is None:
        continue
      if state in frame.function_name:
        return frame
  return None


def get_error_source_info(crash_info):
  """Returns the filename and the line where the bug occurred."""
  frame = get_error_frame(crash_info)
  if not frame:
    return (None, 1)
  try:
    return redact_src_path(frame.filename), int(frame.fileline or 1)
  except TypeError:
    return (None, 1)


def get_rule_index(crash_type):
  """Returns the rule index describe the rule that |crash_type| ran afoul of."""
  # Don't include "READ" or "WRITE" or number of bytes.
  crash_type = crash_type.replace('\n', ' ').split(' ')[0].lower()
  logging.info('crash_type: %s.', crash_type)
  for idx, rule in enumerate(SARIF_RULES):
    if rule['id'] == crash_type:
      logging.info('Rule index: %d.', idx)
      return idx

  return get_rule_index('no-crashes')


def get_sarif_data(stacktrace, target_path):
  """Returns a description of the crash in SARIF."""
  data = copy.deepcopy(SARIF_DATA)
  if stacktrace is None:
    return data

  fuzz_target = os.path.basename(target_path)
  stack_parser = stacktraces.StackParser(fuzz_target=fuzz_target,
                                         symbolized=True,
                                         detect_ooms_and_hangs=True,
                                         include_ubsan=True)
  crash_info = stack_parser.parse(stacktrace)
  error_source_info = get_error_source_info(crash_info)
  rule_idx = get_rule_index(crash_info.crash_type)
  rule_id = SARIF_RULES[rule_idx]['id']
  uri = error_source_info[0]

  result = {
      'level': 'error',
      'message': {
          'text': crash_info.crash_type
      },
      'locations': [{
          'physicalLocation': {
              'artifactLocation': {
                  'uri': uri,
                  'index': 0
              },
              'region': {
                  'startLine': error_source_info[1],
                  # We don't have this granualarity fuzzing.
                  'startColumn': 1,
              }
          }
      }],
      'ruleId': rule_id,
      'ruleIndex': rule_idx
  }
  if uri:
    data['runs'][0]['results'].append(result)
  return data


def write_stacktrace_to_sarif(stacktrace, target_path, workspace):
  """Writes a description of the crash in stacktrace to a SARIF file."""
  data = get_sarif_data(stacktrace, target_path)
  if not os.path.exists(workspace.sarif):
    os.makedirs(workspace.sarif)
  with open(os.path.join(workspace.sarif, 'results.sarif'), 'w') as file_handle:
    file_handle.write(json.dumps(data))
