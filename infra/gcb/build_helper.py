"""Utility module for Google Cloud Build scripts."""
import datetime
import json
import os
import requests
import sys
import urlparse

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

# Needed for reading public target.list.* files.
GCS_URL_BASENAME = 'https://storage.googleapis.com/'

# Where corpus backups can be downloaded from.
CORPUS_BACKUP_URL = ('/{project}-backup.clusterfuzz-external.appspot.com/'
                     'corpus/libFuzzer/{fuzzer}/latest.zip')

# Cloud Builder has a limit of 100 build steps and 100 arguments for each step.
CORPUS_DOWNLOAD_BATCH_SIZE = 100


def _get_targets_list(project_name):
  # libFuzzer ASan is the default configuration, get list of targets from it.
  url = build_project.get_targets_list_url(
      build_project.ENGINE_INFO['libfuzzer'].upload_bucket, project_name,
      'address')

  url = urlparse.urljoin(GCS_URL_BASENAME, url)
  r = requests.get(url)
  if not r.status_code == 200:
    sys.stderr.write('Failed to get list of targets from "%s".\n' % url)
    sys.stderr.write('Status code: %d \t\tText:\n%s\n' %
                     (r.status_code, r.text))
    return None

  return r.text.split()


def download_corpora_step(project_name):
  """Returns a GCB step for downloading corpora backups for the given project.
  """
  fuzz_targets = _get_targets_list(project_name)
  if not fuzz_targets:
    sys.stderr.write('No fuzz targets found for project "%s".\n' % project_name)
    return None

  # Split fuzz targets into batches of CORPUS_DOWNLOAD_BATCH_SIZE.
  for i in xrange(0, len(fuzz_targets), CORPUS_DOWNLOAD_BATCH_SIZE):
    download_corpus_args = []
    for binary_name in fuzz_targets[i:i + CORPUS_DOWNLOAD_BATCH_SIZE]:
      qualified_name = binary_name
      qualified_name_prefix = '%s_' % project_name
      if not binary_name.startswith(qualified_name_prefix):
        qualified_name = qualified_name_prefix + binary_name

      url = build_project.get_signed_url(CORPUS_BACKUP_URL.format(
          project=project_name, fuzzer=qualified_name),
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
