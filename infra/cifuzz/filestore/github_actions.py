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
import enum
import json
import urllib.parse
from urllib.parse import urlencode
import os
import tempfile

import utils


import filestore

DIRECTORY = os.path.dirname(__file__)

class GithubActionsFilestore(BaseFilestore):

  NODE_BIN = 'nodejs'
  UPLOAD_SCRIPT = os.path.join(DIRECTORY, github_actions_js, 'upload.js')

  def upload_directory(self, name, directory):
    directory = os.path.abspath(directory)

    # Get file paths.
    file_paths = []
    for root, _, curr_file_paths in os.walk(directory):
      for file_path in curr_file_paths:
        file_paths.append(os.path.join(root, file_path))

    # !!! Zip?

    return upload_artifact(name, file_paths, directory)


def upload_artifact(name, files, root_directory, options=None):
  """artifact-client.js"""
  check_artifact_name(name)
  upload_specification = get_upload_specification(
      name, root_directory, file_paths)

  upload_response = {
      artifactName: name
      artifactItems: [],
      size: 0,
      failedItems: []
  }
  if upload_specification.length == 0:
    raise Exception('No files to upload.')
  else:
    response = create_artifact_in_file_container(name, options)
    if response['fileContainerResourceUrl']:
      logging.debug('create_artifact_in_file_container response: %s.',
                    response)
      raise Exception('GitHub artifacts API didn\'t provid upload URL.')
    logging.debug('Upload resource URL: %s',
                  response['fileContainerResourceUrl'])
    upload_result = upload_artifact_to_file_container(
        response['fileContainerResourceUrl'], upload_specification, options)
    # Update artifact size when done.
    # Uncompressed size used in UI when downloading a zip of the artifact.
    patch_artifact_size(upload_result['totalSize'], name)
    logging.info('Uploaded artifact: %s, size is: %s bytes, '
                 '%d items failed to upload.',
                 name,  upload_result['uploadSize'],
                 upload_result['failedItems']['length'])
    upload_response['artifactItems'] = [item['absoluteFilePath']
                                        for item in upload_specification]
    upload_response['size'] = upload_result['uploadSize']
    upload_response['failedItems'] = upload_result['failedItems']
    return upload_response


# http-client/index.js
class HTTPCode(enum.Enum):
  BAD_REQUEST = 400
  FORBIDDEN = 403
  NOT_FOUND = 404



def upload_artifact_to_file_container(upload_url, files_to_upload, options):
  """upload-http-client.js."""
  logging.debug('concurrency: %d, and chunk size: %d.',
                UPLOAD_FILE_CONCURRENCY, UPLOAD_CHUNK_SIZE)
  # By default, file uploads will continue if there is an error unless specified
  # differently in the options.
  continue_on_error = True
  if options:
    if options.get('continue_on_error') is False:
      continue_on_error = False

  # Prepare the necessary parameters to upload all the files.
  completed_files = 0
  upload_file_size = 0
  total_file_size = 0
  failed_items_to_report = []
  for file_to_upload in files_to_upload:
    url_params = {'itemPath': file_to_upload['uploadFilePath']}
    resource_url = _add_url_params(url_params)
    upload_parameters = {
        'file': file_to_upload,
        'resourceUrl': resource_url,
        'maxChunkSize': MAX_CHUNK_SIZE,
        'continueOnError': continue_on_error
    }
    upload_file_result = upload_file(file_to_upload, upload_parameters)
    upload_file_size += upload_file_result['successfulUploadSize']
    total_file_size += upload_file_result['totalSize']
    if not upload_file_result.is_success:
      failed_items_to_report.append(file_to_upload)
      if not continue_on_error:
        logging.error('Stopping artifact upload due to error.')
        # !!! What do I do here?

    logging.info('Total size of files uploaded is %s bytes.',
                 upload_file_size);
    return {
        'uploadSize': upload_file_size,
        'totalSize': total_file_size,
        'failedItemsToReport': failed_items_to_report
    }



def upload_file(parameters):
  """Based on uploadFileAsync upload-http-client.ts. Note that this doesn't take
  index because we don't need it to do HTTP requests like the typescript code
  does."""
  # !!!
  # Skip gzip as it is unneeded for now.
  total_file_size = os.path.size(parameters['file']['absolutePath'])
  if not upload_chunk(parameters['resourceUrl'], stream, total_file_size, total_file_size):
    return {
        'isSuccess': False,
        'successfulUploadSize': 0,
        'totalSize': total_file_size
    }
  return {
        'isSuccess': True,
        'successfulUploadSize': total_file_size,
        'totalSize': total_file_size
    }

def is_success_status_code(status_code):
  return status_code >= 200 and status code < 300
def upload_chunk(resource_url, stream, upload_file_size, total_file_size):
  """Based on uploadChunk from upload-http-client.ts. Differences from
  typescript code include:
  1. HTTP client index since we don't need it to do HTTP uploads like typescript
  code.
  2. GZIP.
  """
  start = 0
  end = total_file_size - 1
  content_range = get_content_range(start, end, total_file_size)
  upload_headers = get_upload_headers('application/octet-stream',
                                      is_keep_alive=False, is_gzip=False, content_length=total_file_size, content_range=content_range)
  for _ in range(MAX_API_ATTEMPTS):

# From config-variables.js
UPLOAD_CHUNK_SIZE = 8 * 1024 ** 2  # 8 MB.
UPLOAD_FILE_CONCURRENCY = 2



def _add_url_params(url, params):
  """Returns |url| with the specified query |params| added."""
  # It's OK we use _asdict(), this is actually a public method.
  url_parts = urllib.parse(url)._asdict()  # Parse URL into mutable format.

  # Update URL.
  query = urllib.parse.parse_qsl(url_parts['query'])
  query.update(params)
  url_parts['query'] = urlencode(query)

  # Return an URL string.
  return urlparse.urlunparse(urllib.parse.ParseResult(**url_parts))


def patch_artifact_size(size, artifact_name):
  """upload-http-client.js"""
  resource_url = get_artifact_url()
  resource_url = _add_url_params(resource_url, {'artifactName', artifact_name})
  logging.debug('resource_url is %s.', resource_url)
  parameters = {'Size': size}
  data = json.dumps(parameters)
  headers = get_upload_headers('application/json')
  for _ in range(MAX_API_ATTEMPTS):
    # !!! Create better method for handling.
    try:
      do_post_request(resource_url, data, headers)
      break
    except urllib.error.HTTPError as http_error:
      if code == HTTPCode.BAD_REQUEST:
        raise Exception(
            'Artifact {artifact_name}" not found.'.format(
                artifact_name=artifact_name))

    except ConnectionResetError:
      pass

    time.sleep(SLEEP_TIME)
    logging.debug('Artifact "%s" successfully uploaded. Size: %d bytes',
                  artifact_name, size);

INVALID_ARTIFACT_FILEPATH_CHARACTERS = [
    '"', ':', '<', '>', '|', '*', '?',
]
INVALID_ARTIFACT_NAME_CHARACTERS = [
    '\\',
    '/'
] + INVALID_ARTIFACT_FILEPATH_CHARACTERS

def check_artifact_name(name):
  """utils.js checkArtifactName."""
  for char in INVALID_ARTIFACT_NAME_CHARACTERS:
    if char in name:
      raise Exception(
          ('Artifact name is invalid: {name}. '
          'Contains char: "{invalid_char}. '
          'Invalid chars are: {invalid_artifact_name_characters}.').format(
              name=name, invalid_char=invalid_char, invalid_artifact_name_characters=INVALID_ARTIFACT_NAME_CHARACTERS))


def check_artifact_file_path(artifact_file_path):
  """utils.js"""
  if not path:
    raise Exception('Artifact file path does not exist', artifact_file_path)

  for char in INVALID_ARTIFACT_NAME_CHARACTERS:
    if char in artifact_file_path:
      raise Exception(
          ('Artifact path: {artifact_file_path} is invalid, contains '
           'invalid char: {char=char}.').format(
               artifact_file_path=artifact_file_path, char=char))


def get_upload_specification(artifact_name, root_directory, artifact_files):
  specifications = []
  for artifact_file in artifact_files:
    if not os.path.exists(artifact_file):
      raise Exception('File does not exist.', artifact_file)

    # !!! We won't get any dirs.
    if not os.isdir(artifact_file):
      artifact_file = os.path.normpath(artifact_file)
      if not artifact_file.startswith(root_directory):
        raise Exception('Root directory is not a parent of artifact.', root_directory, artifact_file)
      # !!! What about leading /
      upload_path = replace(root_directory, '')
      # !!! resolve?
      check_artifact_file_path(artifact_file)
      specifications.append({
          'absoluteFilePath': artifact_file,
          'uploadFilePath': os.path.join(artifact_name, upload_path)
      })

def get_retention_days():
  return os.environ.get('GITHUB_RETENTION_DAYS')

MAX_API_ATTEMPTS = 5
SLEEP_TIME = 1


def get_proper_retention(retention_input, retention_setting):
  """utils.js"""
  if retention_input < 0:
    raise Exception('Invalid retention, minimum value is 1.')

  retention = retention_input
  if retention_setting:
    max_retention = int(retention_setting)
    logging.warn('Retention days is greater than max allowed by the repository.'
                 ' Reducing retention to %d days', max_rentention)
    retention = max_retention
  return retention

def create_artifact_in_file_container(artifact_name, options):
  """upload-http-client.js"""
  parameters = {
      'Type': 'actions_storage',
      'Name', artifact_name,
  }

  # Set retention period.
  if options and 'retentionDays' in options:
    max_retention_str = get_retention_days()
    parameters['RetentionDays'] = get_proper_retention(
        options['retentionDays'], max_retention_str)

  data = json.dumps(paramaters)
  artifact_url = get_artifact_url()
  headers = get_upload_headers('application/json')
  for _ in range(MAX_API_ATTEMPTS):
    try:
      response = do_post_request(url, data, headers)
      return json.loads(response.read())
    except urllib.error.HTTPError as http_error:
      code = http_error.getcode()
      if code == HTTPCode.BAD_REQUEST:
        raise Exception(
            ('Invalid artifact name: {artifact_name}. '
             'Request URL {artifact_url}.').format(
                 artifact_name=artifact_name, artifact_url=artifact_url))
      elif code == HTTPCode.FORBIDDEN:
        raise Exception('Unable to upload artifacts. Storage quota reached.')
      # Otherwise we can retry.

    except ConnectionResetError:
      pass

    time.sleep(SLEEP_TIME)

  raise Exception('Can\'t retry creating artifact in file container again.')

# !!! Convert exceptions to special kind.

def get_content_range(start, end, total):
  """utils.ts"""
  return 'bytes {start}-{end}/{total}'.format(
      start=start, end=end, total=total)

def get_upload_headers(content_type=None, is_keep_alive=False, is_gzip=None, uncompresed_length=None, content_length=None, content_range=None):
  """utils.js"""
  request_options = {}
  api_version = get_api_version()
  request_options['Accept'] = (
      'application/json;api-version={api_version}'.format(
          api_version=api_version))

  if content_type:
    request_options['Content-Type'] = content_type

  if is_keep_alive:
    request_options['Connection'] = 'Keep-Alive'
    request_options['Keep-Alive'] = '10'

  if is_gzip:
    assert uncompressed_length is not None
    request_options['Content-Encoding'] = 'gzip'
    request_options['x-tfs-filelength'] = uncompressed_length

  if content_length:
    request_options['Content-Length'] = content_length

  if content_range:
    request_options['Content-Range'] = content_range

  return request_options



def do_post_request(url, data, headers={}):
  post_request = request.Request(url, parse.urlencode(data), headers)
  # !!! test error handling.
  return request.urlopen(post_request)

def get_api_version():
  """utils.js"""
  return '6.0-preview'

def get_runtime_url():
  """config-variables.js"""
  token = os.environ.get('ACTIONS_RUNTIME_TOKEN')
  if not token:
    raise Exception('Unable to get ACTIONS_RUNTIME_TOKEN env variable')
  return token

def get_work_flow_run_id():
  work_flow_run_id = os.environ.get('GITHUB_RUN_ID')
  if not work_flow_run_id:
    raise Exception('Unable to get GITHUB_RUN_ID env variable.')
  return work_flow_run_id

def get_artifact_url():
  """utils.js"""
  runtime_url = get_runtime_url()
  work_flow_run_id = get_work_flow_run_id()
  api_version = get_api_version()
  return ('{runtime_url}_apis/pipelines/workflows/{work_flow_run_id}/artifacts?api-versions={api_version}'
