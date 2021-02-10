import os
import time

from github_actions_toolkit.artifact import utils
from github_actions_toolkit import http_client

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
  for _ in range(utils.MAX_API_ATTEMPTS):
    # !!!

def patch_artifact_size(size, artifact_name):
  """upload-http-client.js"""
  resource_url = utils.get_artifact_url()
  resource_url = _add_url_params(resource_url, {'artifactName', artifact_name})
  logging.debug('resource_url is %s.', resource_url)
  parameters = {'Size': size}
  data = json.dumps(parameters)
  headers = get_upload_headers('application/json')
  for _ in range(utils.MAX_API_ATTEMPTS):
    # !!! Create better method for handling.
    try:
      do_post_request(resource_url, data, headers)
      break
    except urllib.error.HTTPError as http_error:
      if code == http_client.HTTPCode.BAD_REQUEST:
        raise Exception(
            'Artifact {artifact_name}" not found.'.format(
                artifact_name=artifact_name))

    except ConnectionResetError:
      pass

    time.sleep(utils.SLEEP_TIME)
    logging.debug('Artifact "%s" successfully uploaded. Size: %d bytes',
                  artifact_name, size);


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
      utils.check_artifact_file_path(artifact_file)
      specifications.append({
          'absoluteFilePath': artifact_file,
          'uploadFilePath': os.path.join(artifact_name, upload_path)
      })

def create_artifact_in_file_container(artifact_name, options):
  """upload-http-client.js"""
  parameters = {
      'Type': 'actions_storage',
      'Name', artifact_name,
  }

  # Set retention period.
  if options and 'retentionDays' in options:
    max_retention_str = config_variables.get_retention_days()
    parameters['RetentionDays'] = get_proper_retention(
        options['retentionDays'], max_retention_str)

  data = json.dumps(paramaters)
  artifact_url = utils.get_artifact_url()
  headers = get_upload_headers('application/json')
  for _ in range(utils.MAX_API_ATTEMPTS):
    try:
      response = do_post_request(url, data, headers)
      return json.loads(response.read())
    except urllib.error.HTTPError as http_error:
      code = http_error.getcode()
      if code == http_client.HTTPCode.BAD_REQUEST:
        raise Exception(
            ('Invalid artifact name: {artifact_name}. '
             'Request URL {artifact_url}.').format(
                 artifact_name=artifact_name, artifact_url=artifact_url))
      elif code == http_client.HTTPCode.FORBIDDEN:
        raise Exception('Unable to upload artifacts. Storage quota reached.')
      # Otherwise we can retry.

    except ConnectionResetError:
      pass

    time.sleep(utils.SLEEP_TIME)

  raise Exception('Can\'t retry creating artifact in file container again.')


def do_post_request(url, data, headers={}):
  post_request = request.Request(url, parse.urlencode(data), headers)
  # !!! test error handling.
  return request.urlopen(post_request)


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


def _add_url_params(url, params):
  """Returns |url| with the specified query |params| added."""
  # It's OK we use _asdict(), this is actually a public method.
  url_parts = urllib.parse(url)._asdict()  # Parse URL into mutable format.

  # Update URL.
  query = urllib.parse.parse_qsl(url_parts['query'])
  query.update(params)
  url_parts['query'] = urlencode(query)

  # Return a URL string.
  return urlparse.urlunparse(urllib.parse.ParseResult(**url_parts))
