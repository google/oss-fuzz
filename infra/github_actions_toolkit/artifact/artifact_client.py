import logging

from github_actions_toolkit.artifact import utils
from github_actions_toolkit.artifact import http_upload_client

def upload_artifact(name, files, root_directory, options=None):
  """artifact-client.js"""
  utils.check_artifact_name(name)
  upload_specification = http_upload_client.get_upload_specification(
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
    response = http_upload_client.create_artifact_in_file_container(
        name, options)
    if response['fileContainerResourceUrl']:
      logging.debug('create_artifact_in_file_container response: %s.',
                    response)
      raise Exception('GitHub artifacts API didn\'t provid upload URL.')
    logging.debug('Upload resource URL: %s',
                  response['fileContainerResourceUrl'])
    upload_result = http_upload_client.upload_artifact_to_file_container(
        response['fileContainerResourceUrl'], upload_specification, options)
    # Update artifact size when done.
    # Uncompressed size used in UI when downloading a zip of the artifact.
    http_upload_client.patch_artifact_size(upload_result['totalSize'], name)
    logging.info('Uploaded artifact: %s, size is: %s bytes, '
                 '%d items failed to upload.',
                 name,  upload_result['uploadSize'],
                 upload_result['failedItems']['length'])
    upload_response['artifactItems'] = [item['absoluteFilePath']
                                        for item in upload_specification]
    upload_response['size'] = upload_result['uploadSize']
    upload_response['failedItems'] = upload_result['failedItems']
    return upload_response
