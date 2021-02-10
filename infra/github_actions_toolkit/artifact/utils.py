import logging


from github_actions_toolkit.artifact import config_variables

MAX_API_ATTEMPTS = 5
SLEEP_TIME = 1
INVALID_ARTIFACT_FILEPATH_CHARACTERS = [
    '"', ':', '<', '>', '|', '*', '?',
]
INVALID_ARTIFACT_NAME_CHARACTERS = [
    '\\',
    '/'
] + INVALID_ARTIFACT_FILEPATH_CHARACTERS


# !!! Convert exceptions to special kind.


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

def get_api_version():
  """utils.js"""
  return '6.0-preview'

def get_artifact_url():
  """utils.js"""
  runtime_url = config_variables.get_runtime_url()
  work_flow_run_id = config_variables.get_work_flow_run_id()
  api_version = get_api_version()
  return ('{runtime_url}_apis/pipelines/workflows/{work_flow_run_id}/artifacts?api-versions={api_version}'
