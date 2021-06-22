"""Public interface for artifact. Based on artifact-client.ts"""
import logging

from third_party.github_actions_toolkit.artifact import utils
from third_party.github_actions_toolkit.artifact import upload_http_client
from third_party.github_actions_toolkit.artifact import upload_specification


def upload_artifact(name, files, root_directory, options=None):
  """Uploads an artifact based on uploadArtifact."""
  utils.check_artifact_name(name)
  upload_spec = upload_specification.get_upload_specification(
      name, root_directory, files)

  upload_response = {
      'artifactName': name,
      'artifactItems': [],
      'size': 0,
      'failedItems': []
  }
  if len(upload_spec) == 0:
    raise Exception('No files to upload')

  response = upload_http_client.create_artifact_in_file_container(name, options)
  file_container_resource_url = response.get('fileContainerResourceUrl')
  if not file_container_resource_url:
    logging.debug('create_artifact_in_file_container response: %s.', response)
    raise Exception('GitHub artifacts API didn\'t provide upload URL')

  logging.debug('Upload resource URL: %s', file_container_resource_url)
  upload_result = upload_http_client.upload_artifact_to_file_container(
      file_container_resource_url, upload_spec, options)
  # Update artifact size when done.
  # Uncompressed size used in UI when downloading a zip of the artifact.
  upload_http_client.patch_artifact_size(upload_result['totalSize'], name)
  logging.info(
      'Uploaded artifact: %s, size is: %s bytes, '
      '%d items failed to upload.', name, upload_result['uploadSize'],
      len(upload_result['failedItems']))
  upload_response['artifactItems'] = [
      spec.absolute_file_path for spec in upload_spec
  ]
  upload_response['size'] = upload_result['uploadSize']
  upload_response['failedItems'] = upload_result['failedItems']
  return upload_response
