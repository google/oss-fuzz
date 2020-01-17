"""Utility module for Google Cloud Build scripts."""
import base64
import collections
import os
import requests
import sys
import time
import urllib
import urlparse

from oauth2client.service_account import ServiceAccountCredentials

BUILD_TIMEOUT = 12 * 60 * 60

# Needed for reading public target.list.* files.
GCS_URL_BASENAME = 'https://storage.googleapis.com/'

GCS_UPLOAD_URL_FORMAT = '/{0}/{1}/{2}'

# Where corpus backups can be downloaded from.
CORPUS_BACKUP_URL = ('/{project}-backup.clusterfuzz-external.appspot.com/'
                     'corpus/libFuzzer/{fuzzer}/latest.zip')

# Cloud Builder has a limit of 100 build steps and 100 arguments for each step.
CORPUS_DOWNLOAD_BATCH_SIZE = 100

TARGETS_LIST_BASENAME = 'targets.list'

EngineInfo = collections.namedtuple(
    'EngineInfo',
    ['upload_bucket', 'supported_sanitizers', 'supported_architectures'])

ENGINE_INFO = {
    'libfuzzer':
        EngineInfo(upload_bucket='clusterfuzz-builds',
                   supported_sanitizers=['address', 'memory', 'undefined'],
                   supported_architectures=['x86_64', 'i386']),
    'afl':
        EngineInfo(upload_bucket='clusterfuzz-builds-afl',
                   supported_sanitizers=['address'],
                   supported_architectures=['x86_64']),
    'honggfuzz':
        EngineInfo(upload_bucket='clusterfuzz-builds-honggfuzz',
                   supported_sanitizers=['address', 'memory', 'undefined'],
                   supported_architectures=['x86_64']),
    'dataflow':
        EngineInfo(upload_bucket='clusterfuzz-builds-dataflow',
                   supported_sanitizers=['dataflow'],
                   supported_architectures=['x86_64']),
    'none':
        EngineInfo(upload_bucket='clusterfuzz-builds-no-engine',
                   supported_sanitizers=['address'],
                   supported_architectures=['x86_64']),
}


def get_targets_list_filename(sanitizer):
  return TARGETS_LIST_BASENAME + '.' + sanitizer


def get_targets_list_url(bucket, project, sanitizer):
  filename = get_targets_list_filename(sanitizer)
  url = GCS_UPLOAD_URL_FORMAT.format(bucket, project, filename)
  return url


def _get_targets_list(project_name):
  # libFuzzer ASan is the default configuration, get list of targets from it.
  url = get_targets_list_url(ENGINE_INFO['libfuzzer'].upload_bucket,
                             project_name, 'address')

  url = urlparse.urljoin(GCS_URL_BASENAME, url)
  response = requests.get(url)
  if not response.status_code == 200:
    sys.stderr.write('Failed to get list of targets from "%s".\n' % url)
    sys.stderr.write('Status code: %d \t\tText:\n%s\n' %
                     (response.status_code, response.text))
    return None

  return response.text.split()


def get_signed_url(path, method='PUT', content_type=''):
  timestamp = int(time.time() + BUILD_TIMEOUT)
  blob = '{0}\n\n{1}\n{2}\n{3}'.format(method, content_type, timestamp, path)

  creds = ServiceAccountCredentials.from_json_keyfile_name(
      os.environ['GOOGLE_APPLICATION_CREDENTIALS'])
  client_id = creds.service_account_email
  signature = base64.b64encode(creds.sign_blob(blob)[1])
  values = {
      'GoogleAccessId': client_id,
      'Expires': timestamp,
      'Signature': signature,
  }

  return ('https://storage.googleapis.com{0}?'.format(path) +
          urllib.urlencode(values))


def download_corpora_step(project_name):
  """Returns a GCB step for downloading corpora backups for the given project.
  """
  fuzz_targets = _get_targets_list(project_name)
  if not fuzz_targets:
    sys.stderr.write('No fuzz targets found for project "%s".\n' % project_name)
    return None

  # Split fuzz targets into batches of CORPUS_DOWNLOAD_BATCH_SIZE.
  for i in range(0, len(fuzz_targets), CORPUS_DOWNLOAD_BATCH_SIZE):
    download_corpus_args = []
    for binary_name in fuzz_targets[i:i + CORPUS_DOWNLOAD_BATCH_SIZE]:
      qualified_name = binary_name
      qualified_name_prefix = '%s_' % project_name
      if not binary_name.startswith(qualified_name_prefix):
        qualified_name = qualified_name_prefix + binary_name

      url = get_signed_url(CORPUS_BACKUP_URL.format(project=project_name,
                                                    fuzzer=qualified_name),
                           method='GET')

      corpus_archive_path = os.path.join('/corpus', binary_name + '.zip')
      download_corpus_args.append('%s %s' % (corpus_archive_path, url))

    step = {
        'name': 'gcr.io/oss-fuzz-base/base-runner',
        'entrypoint': 'download_corpus',
        'args': download_corpus_args,
        'volumes': [{
            'name': 'corpus',
            'path': '/corpus'
        }],
    }
    return step
