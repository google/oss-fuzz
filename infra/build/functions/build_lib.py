# Copyright 2020 Google Inc.
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
#
################################################################################
"""Utility module for Google Cloud Build scripts."""
import base64
import binascii
import collections
import dataclasses
import datetime
import json
import logging
import os
import re
import six.moves.urllib.parse as urlparse
import sys
import time
import tarfile
import tempfile
import uuid

from googleapiclient.discovery import build as cloud_build
import googleapiclient.discovery
import google.api_core.client_options
import google.auth
from google.cloud import storage
from oauth2client import service_account as service_account_lib
import requests
import yaml

BASE_IMAGES_PROJECT = 'oss-fuzz-base'
IMAGE_PROJECT = 'oss-fuzz'

BUILD_TIMEOUT = 20 * 60 * 60

# Needed for reading public target.list.* files.
GCS_URL_BASENAME = 'https://storage.googleapis.com/'

GCS_UPLOAD_URL_FORMAT = '/{0}/{1}/{2}'

# Where corpus backups can be downloaded from.
CORPUS_BACKUP_URL = ('/{project}-backup.clusterfuzz-external.appspot.com/'
                     'corpus/libFuzzer/{fuzzer}/latest.zip')

# Regex to match special chars in project name.
SPECIAL_CHARS_REGEX = re.compile('[^a-zA-Z0-9_-]')

# Cloud Builder has a limit of 100 build steps and 100 arguments for each step.
CORPUS_DOWNLOAD_BATCH_SIZE = 100

TARGETS_LIST_BASENAME = 'targets.list'

EngineInfo = collections.namedtuple(
    'EngineInfo',
    ['upload_bucket', 'supported_sanitizers', 'supported_architectures'])


@dataclasses.dataclass
class SignedPolicyDocument:
  """Signed policy document"""
  bucket: str
  policy: str
  x_goog_algorithm: str
  x_goog_date: str
  x_goog_credential: str
  x_goog_signature: str


ENGINE_INFO = {
    'libfuzzer':
        EngineInfo(upload_bucket='clusterfuzz-builds',
                   supported_sanitizers=['address', 'memory', 'undefined'],
                   supported_architectures=['x86_64', 'i386', 'aarch64']),
    'afl':
        EngineInfo(upload_bucket='clusterfuzz-builds-afl',
                   supported_sanitizers=['address'],
                   supported_architectures=['x86_64']),
    'honggfuzz':
        EngineInfo(upload_bucket='clusterfuzz-builds-honggfuzz',
                   supported_sanitizers=['address'],
                   supported_architectures=['x86_64']),
    'none':
        EngineInfo(upload_bucket='clusterfuzz-builds-no-engine',
                   supported_sanitizers=['address'],
                   supported_architectures=['x86_64']),
    'wycheproof':
        EngineInfo(upload_bucket='clusterfuzz-builds-wycheproof',
                   supported_sanitizers=['none'],
                   supported_architectures=['x86_64']),
    'centipede':
        EngineInfo(upload_bucket='clusterfuzz-builds-centipede',
                   supported_sanitizers=['address', 'none'],
                   supported_architectures=['x86_64']),
}

OSS_FUZZ_BUILDPOOL_NAME = os.getenv(
    'GCB_BUILDPOOL_NAME', 'projects/oss-fuzz/locations/us-central1/'
    'workerPools/buildpool')

OSS_FUZZ_INDEXER_BUILDPOOL_NAME = os.getenv(
    'GCB_BUILDPOOL_NAME', 'projects/oss-fuzz/locations/us-central1/'
    'workerPools/indexer-buildpool')

OSS_FUZZ_EXPERIMENTS_BUILDPOOL_NAME = os.getenv(
    'GCB_BUILDPOOL_NAME', 'projects/oss-fuzz/locations/us-central1/'
    'workerPools/buildpool-experiments')

CLOUD_BUILD_LOCATION = os.getenv('CLOUD_BUILD_LOCATION', 'us-central1')
REGIONAL_CLIENT_OPTIONS = google.api_core.client_options.ClientOptions(
    api_endpoint=f'https://{CLOUD_BUILD_LOCATION}-cloudbuild.googleapis.com/')

DOCKER_TOOL_IMAGE = 'gcr.io/cloud-builders/docker'

_ARM64 = 'aarch64'

OSS_FUZZ_ROOT = os.path.abspath(os.path.join(__file__, '..', '..', '..', '..'))


def get_targets_list_filename(sanitizer):
  """Returns target list filename."""
  return TARGETS_LIST_BASENAME + '.' + sanitizer


def get_targets_list_url(bucket, project, sanitizer):
  """Returns target list url."""
  filename = get_targets_list_filename(sanitizer)
  url = GCS_UPLOAD_URL_FORMAT.format(bucket, project, filename)
  return url


def dockerify_run_step(step, build, use_architecture_image_name=False):
  """Modify a docker run step to run using gcr.io/cloud-builders/docker. This
  allows us to specify which architecture to run the image on."""
  image = step['name']
  if use_architecture_image_name:
    image = _make_image_name_architecture_specific(image, build.architecture)
  step['name'] = DOCKER_TOOL_IMAGE
  if build.is_arm:
    platform = 'linux/arm64'
  else:
    platform = 'linux/amd64'
  new_args = [
      'run', '--platform', platform, '-v', '/workspace:/workspace',
      '--privileged', '--cap-add=all'
  ]
  for env_var in step.get('env', {}):
    new_args.extend(['-e', env_var])
  new_args += ['-t', image]
  new_args += step['args']
  step['args'] = new_args
  return step


def get_upload_bucket(engine, architecture, testing):
  """Returns the upload bucket for |engine| and architecture. Returns the
  testing bucket if |testing|."""
  bucket = ENGINE_INFO[engine].upload_bucket
  if architecture != 'x86_64':
    bucket += '-' + architecture
  if testing:
    bucket += '-testing'
  return bucket


def _get_targets_list(project_name):
  """Returns target list."""
  # libFuzzer ASan 'x86_84' is the default configuration, get list of targets
  # from it.
  # We never want the target list from the testing bucket, the testing bucket is
  # only for uploading.
  bucket = get_upload_bucket('libfuzzer', 'x86_64', testing=None)
  url = get_targets_list_url(bucket, project_name, 'address')

  url = urlparse.urljoin(GCS_URL_BASENAME, url)
  response = requests.get(url)
  if not response.status_code == 200:
    sys.stderr.write('Failed to get list of targets from "%s".\n' % url)
    sys.stderr.write('Status code: %d \t\tText:\n%s\n' %
                     (response.status_code, response.text))
    return None

  return response.text.split()


def _sign_client_id():
  service_account_path = os.environ.get('GOOGLE_APPLICATION_CREDENTIALS')
  if service_account_path:
    creds = (
        service_account_lib.ServiceAccountCredentials.from_json_keyfile_name(
            os.environ['GOOGLE_APPLICATION_CREDENTIALS']))
    return creds.service_account_email
  else:
    _, project = google.auth.default()
    return project + '@appspot.gserviceaccount.com'


def _sign_blob(blob):
  service_account_path = os.environ.get('GOOGLE_APPLICATION_CREDENTIALS')
  if service_account_path:
    creds = (
        service_account_lib.ServiceAccountCredentials.from_json_keyfile_name(
            os.environ['GOOGLE_APPLICATION_CREDENTIALS']))
    client_id = creds.service_account_email
    signature = base64.b64encode(creds.sign_blob(blob)[1])
  else:
    credentials, project = google.auth.default()
    iam = googleapiclient.discovery.build('iamcredentials',
                                          'v1',
                                          credentials=credentials,
                                          cache_discovery=False)
    client_id = project + '@appspot.gserviceaccount.com'
    service_account = f'projects/-/serviceAccounts/{client_id}'
    response = iam.projects().serviceAccounts().signBlob(
        name=service_account,
        body={
            'delegates': [],
            'payload': base64.b64encode(blob.encode('utf-8')).decode('utf-8'),
        }).execute()
    signature = response['signedBlob']

  return client_id, signature


# TODO(ochang): Migrate older signed URLs to V4 signatures.
def get_signed_policy_document_upload_prefix(bucket, path_prefix):
  now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
  timestamp = now.strftime('%Y%m%dT%H%M%SZ')
  datestamp = now.date().strftime('%Y%m%d')
  expiry = now + datetime.timedelta(hours=24)

  client_id = _sign_client_id()
  x_goog_credential = f'{client_id}/{datestamp}/auto/storage/goog4_request'

  doc = {
      'expiration':
          expiry.isoformat() + 'Z',
      'conditions': [[
          'starts-with',
          '$key',
          path_prefix,
      ], {
          'bucket': bucket,
      }, {
          'x-goog-algorithm': 'GOOG4-RSA-SHA256'
      }, {
          'x-goog-credential': x_goog_credential
      }, {
          'x-goog-date': timestamp
      }]
  }

  encoded = base64.b64encode(json.dumps(doc).encode()).decode()
  client_id, signature = _sign_blob(encoded)

  return SignedPolicyDocument(
      bucket=bucket,
      policy=encoded,
      x_goog_algorithm='GOOG4-RSA-SHA256',
      x_goog_credential=x_goog_credential,
      x_goog_date=timestamp,
      x_goog_signature=binascii.hexlify(base64.b64decode(signature)).decode(),
  )


# pylint: disable=no-member
def get_signed_url(path, method='PUT', content_type=''):
  """Returns signed url."""
  timestamp = int(time.time() + BUILD_TIMEOUT)
  blob = f'{method}\n\n{content_type}\n{timestamp}\n{path}'

  client_id, signature = _sign_blob(blob)
  values = {
      'GoogleAccessId': client_id,
      'Expires': timestamp,
      'Signature': signature,
  }
  return f'https://storage.googleapis.com{path}?{urlparse.urlencode(values)}'


def _normalized_name(name):
  """Return normalized name with special chars like slash, colon, etc normalized
  to hyphen(-). This is important as otherwise these chars break local and cloud
  storage paths."""
  return SPECIAL_CHARS_REGEX.sub('-', name).strip('-')


def download_corpora_steps(project_name, test_image_suffix):
  """Returns GCB steps for downloading corpora backups for the given project.
  """
  fuzz_targets = _get_targets_list(project_name)
  if not fuzz_targets:
    sys.stderr.write('No fuzz targets found for project "%s".\n' % project_name)
    return None

  steps = []
  # Split fuzz targets into batches of CORPUS_DOWNLOAD_BATCH_SIZE.
  for i in range(0, len(fuzz_targets), CORPUS_DOWNLOAD_BATCH_SIZE):
    download_corpus_args = []
    for binary_name in fuzz_targets[i:i + CORPUS_DOWNLOAD_BATCH_SIZE]:
      qualified_name = binary_name
      qualified_name_prefix = '%s_' % project_name
      if not binary_name.startswith(qualified_name_prefix):
        qualified_name = qualified_name_prefix + binary_name

      # Normalize qualified_name name.
      qualified_name = _normalized_name(qualified_name)

      url = get_signed_url(CORPUS_BACKUP_URL.format(project=project_name,
                                                    fuzzer=qualified_name),
                           method='GET')

      corpus_archive_path = os.path.join('/corpus', binary_name + '.zip')
      download_corpus_args.append('%s %s' % (corpus_archive_path, url))

    steps.append({
        'name': get_runner_image_name(test_image_suffix),
        'entrypoint': 'download_corpus',
        'args': download_corpus_args,
        'volumes': [{
            'name': 'corpus',
            'path': '/corpus'
        }],
    })

  return steps


def download_coverage_data_steps(project_name, latest, bucket_name, out_dir):
  """Returns GCB steps to download coverage data for the given project"""
  steps = []
  fuzz_targets = _get_targets_list(project_name)
  if not fuzz_targets:
    sys.stderr.write('No fuzz targets found for project "%s".\n' % project_name)
    return None

  steps.append({
      'name': 'gcr.io/oss-fuzz-base/base-runner',
      'args': ['bash', '-c', (f'mkdir -p {out_dir}/textcov_reports')]
  })

  coverage_data_path = os.path.join(f'{out_dir}/textcov_reports/')
  bucket_url = f'gs://{bucket_name}/{project_name}/textcov_reports/{latest}/*'
  steps.append({
      'name': 'gcr.io/cloud-builders/gsutil',
      'args': ['-m', 'cp', '-r', bucket_url, coverage_data_path],
      'allowFailure': True
  })
  steps.append({
      'name': 'gcr.io/oss-fuzz-base/base-runner',
      'args': ['bash', '-c', f'ls -lrt {out_dir}/textcov_reports'],
      'allowFailure': True
  })

  return steps


def http_upload_step(data, signed_url, content_type):
  """Returns a GCB step to upload data to the given URL via GCS HTTP API."""
  step = {
      'name':
          'gcr.io/cloud-builders/curl',
      'args': [
          '-H',
          'Content-Type: ' + content_type,
          '-X',
          'PUT',
          '-d',
          data,
          signed_url,
      ],
  }
  return step


def signed_policy_document_curl_args(doc: SignedPolicyDocument):
  """Signed policy document curl args."""
  return [
      '-F',
      'policy=' + doc.policy,
      '-F',
      'x-goog-algorithm=' + doc.x_goog_algorithm,
      '-F',
      'x-goog-date=' + doc.x_goog_date,
      '-F',
      'x-goog-credential=' + doc.x_goog_credential,
      '-F',
      'x-goog-signature=' + doc.x_goog_signature,
  ]


def upload_using_signed_policy_document(file_path, upload_path,
                                        doc: SignedPolicyDocument):
  """Upload using signed policy document."""
  step = {
      'name':
          'gcr.io/cloud-builders/curl',
      'args':
          signed_policy_document_curl_args(doc) + [
              '-F',
              f'key={upload_path}',
              '-F',
              f'file=@{file_path}',
              f'https://{doc.bucket}.storage.googleapis.com',
          ]
  }
  return step


def gsutil_rm_rf_step(url):
  """Returns a GCB step to recursively delete the object with given GCS url."""
  step = {
      'name': 'gcr.io/cloud-builders/gsutil',
      'entrypoint': 'sh',
      'args': [
          '-c',
          'gsutil -m rm -rf %s || exit 0' % url,
      ],
  }
  return step


def get_pull_test_images_steps(test_image_suffix):
  """Returns steps to pull testing versions of base-images and tag them so that
  they are used in builds."""
  images = [
      'gcr.io/oss-fuzz-base/base-builder',
      'gcr.io/oss-fuzz-base/base-builder-swift',
      'gcr.io/oss-fuzz-base/base-builder-javascript',
      'gcr.io/oss-fuzz-base/base-builder-jvm',
      'gcr.io/oss-fuzz-base/base-builder-go',
      'gcr.io/oss-fuzz-base/base-builder-python',
      'gcr.io/oss-fuzz-base/base-builder-ruby',
      'gcr.io/oss-fuzz-base/base-builder-rust',
      'gcr.io/oss-fuzz-base/base-builder-ruby',
      'gcr.io/oss-fuzz-base/base-runner',
  ]
  steps = []
  for image in images:
    test_image = image + '-' + test_image_suffix
    steps.append({
        'name': DOCKER_TOOL_IMAGE,
        'args': [
            'pull',
            test_image,
        ],
        'waitFor': '-'  # Start this immediately, don't wait for previous step.
    })

    # This step is hacky but gives us great flexibility. OSS-Fuzz has hardcoded
    # references to gcr.io/oss-fuzz-base/base-builder (in dockerfiles, for
    # example) and gcr.io/oss-fuzz-base-runner (in this build code). But the
    # testing versions of those images are called e.g.
    # gcr.io/oss-fuzz-base/base-builder-testing and
    # gcr.io/oss-fuzz-base/base-runner-testing. How can we get the build to use
    # the testing images instead of the real ones? By doing this step: tagging
    # the test image with the non-test version, so that the test version is used
    # instead of pulling the real one.
    steps.append({
        'name': DOCKER_TOOL_IMAGE,
        'args': ['tag', test_image, image],
    })
  return steps


def get_srcmap_step_id():
  """Returns the id for the srcmap step."""
  return 'srcmap'


def get_git_clone_step(repo_url='https://github.com/google/oss-fuzz.git',
                       branch=None):
  """Returns the git clone step."""
  clone_step = {
      'args': ['clone', repo_url, '--depth', '1'],
      'name': 'gcr.io/cloud-builders/git',
  }
  if branch:
    # Do this to support testing other branches.
    clone_step['args'].extend(['--branch', branch])

  return clone_step


def _make_image_name_architecture_specific(image_name, architecture):
  """Returns an architecture-specific name for |image_name|, based on |build|"""
  return f'{image_name}-{architecture.lower()}'


def get_unique_build_step_image_id():
  return uuid.uuid4()


def get_docker_build_step(image_names,
                          directory,
                          use_buildkit_cache=False,
                          src_root='oss-fuzz',
                          architecture='x86_64',
                          cache_image=''):
  """Returns the docker build step."""
  assert len(image_names) >= 1
  directory = os.path.join(src_root, directory)

  if architecture != _ARM64:
    args = ['build']
  else:
    args = [
        'buildx', 'build', '--platform', 'linux/arm64', '--progress', 'plain',
        '--load'
    ]
    # TODO(metzman): This wont work when we want to build the base-images.
    image_names = [
        _make_image_name_architecture_specific(image_name, architecture)
        for image_name in image_names
    ]
  if cache_image:
    args.extend(['--build-arg', f'CACHE_IMAGE={cache_image}'])

  for image_name in sorted(image_names):
    args.extend(['--tag', image_name])

  step = {
      'name': DOCKER_TOOL_IMAGE,
      'args': args,
      'dir': directory,
      'id': f'build-{get_unique_build_step_image_id()}',
  }
  # Handle buildkit args
  # Note that we mutate "args" after making it a value in step.
  if use_buildkit_cache:
    env = ['DOCKER_BUILDKIT=1']
    step['env'] = env
    args.extend(['--build-arg', 'BUILDKIT_INLINE_CACHE=1'])
    for image in image_names:
      args.extend(['--cache-from', image])

  args.append('.')

  return step


def has_arm_build(architectures):
  """Returns True if project has an ARM build."""
  return 'aarch64' in architectures


def get_srcmap_steps(image, language, directory='/workspace'):
  srcmap_step_id = get_srcmap_step_id()
  return [{
      'name': image,
      'args': [
          'bash', '-c',
          f'srcmap > {directory}/srcmap.json && cat {directory}/srcmap.json'
      ],
      'env': [
          'OSSFUZZ_REVISION=$REVISION_ID',
          f'FUZZING_LANGUAGE={language}',
      ],
      'id': srcmap_step_id
  }]


def get_project_image_steps(  # pylint: disable=too-many-arguments
    name,
    image,
    language,
    config,
    architectures=None,
    experiment=False,
    cache_image=None,
    srcmap=True):
  """Returns GCB steps to build OSS-Fuzz project image."""
  if architectures is None:
    architectures = []

  # TODO(metzman): Pass the URL to clone.
  clone_step = get_git_clone_step(repo_url=config.repo, branch=config.branch)
  if experiment:
    # Skip cloning if we're in an experiment. The source is submitted to GCB
    # via gcloud builds submit.
    steps = []
  else:
    steps = [clone_step]
  if config.test_image_suffix:
    steps.extend(get_pull_test_images_steps(config.test_image_suffix))
  src_root = 'oss-fuzz' if not experiment else '.'

  docker_build_step = get_docker_build_step(
      [image, _get_unsafe_name(name)],
      os.path.join('projects', name),
      src_root=src_root,
      cache_image=cache_image)
  steps.append(docker_build_step)
  if srcmap:
    steps.extend(get_srcmap_steps(image, language))

  if has_arm_build(architectures):
    builder_name = 'buildxbuilder'
    steps.extend([
        {
            'name': 'gcr.io/cloud-builders/docker',
            'args': ['run', '--privileged', 'linuxkit/binfmt:v0.8']
        },
        {
            'name': DOCKER_TOOL_IMAGE,
            'args': ['buildx', 'create', '--name', builder_name]
        },
        {
            'name': DOCKER_TOOL_IMAGE,
            'args': ['buildx', 'use', builder_name]
        },
    ])
    docker_build_arm_step = get_docker_build_step(
        [image, _get_unsafe_name(name)],
        os.path.join('projects', name),
        architecture=_ARM64)
    steps.append(docker_build_arm_step)

  logging.info(f'Considering pushing {config.build_type} {language}.')
  if (config.build_type == 'fuzzing' and language in ('c', 'c++') and
      not not config.testing and not config.experiment and config.upload):
    logging.info('Pushing.')
    # Push so that historical bugs are reproducible.
    push_step = {
        'name': 'gcr.io/cloud-builders/docker',
        'args': ['push', _get_unsafe_name(name)],
        'id': 'push-image',
        'waitFor': [docker_build_step['id']],
        'allowFailure': True
    }
    steps.append(push_step)

  return steps


def _get_unsafe_name(name):
  return f'us-central1-docker.pkg.dev/oss-fuzz/unsafe/{name}'


def get_logs_url(build_id):
  """Returns url that displays the build logs."""
  return (
      f'https://oss-fuzz-gcb-logs.storage.googleapis.com/log-{build_id}.txt')


def get_gcb_url(build_id, cloud_project='oss-fuzz'):
  """Returns url where logs are displayed for the build."""
  return (
      'https://console.cloud.google.com/cloud-build/builds;region=us-central1/'
      f'{build_id}?project={cloud_project}')


def get_runner_image_name(test_image_suffix):
  """Returns the runner image that should be used. Returns the testing image if
  |test_image_suffix|."""
  image = f'gcr.io/{BASE_IMAGES_PROJECT}/base-runner'
  if test_image_suffix:
    image += '-' + test_image_suffix
  return image


def get_build_body(  # pylint: disable=too-many-arguments
    steps,
    timeout,
    body_overrides,
    build_tags,
    use_build_pool=True,
    experiment=False):
  """Helper function to create a build from |steps|."""
  if 'GCB_OPTIONS' in os.environ:
    options = yaml.safe_load(os.environ['GCB_OPTIONS'])
  else:
    options = {}

  if use_build_pool:
    if experiment:
      options['pool'] = {'name': OSS_FUZZ_EXPERIMENTS_BUILDPOOL_NAME}
    # TODO: refactor all of this to make this less ugly.
    elif 'indexer' in build_tags:
      options['pool'] = {'name': OSS_FUZZ_INDEXER_BUILDPOOL_NAME}
    else:
      options['pool'] = {'name': OSS_FUZZ_BUILDPOOL_NAME}

  build_body = {
      'steps': steps,
      'timeout': str(timeout) + 's',
      'options': options,
  }
  if build_tags:
    build_body['tags'] = build_tags

  if body_overrides is None:
    body_overrides = {}
  for key, value in body_overrides.items():
    build_body[key] = value
  return build_body


def _tgz_local_build(oss_fuzz_project, temp_tgz_path):
  """Prepare a .tgz containing the files required to build
  `oss_fuzz_project`."""
  # Just the projects/<project> dir should be sufficient.
  project_rel_path = os.path.join('projects', oss_fuzz_project)
  with tarfile.open(temp_tgz_path, 'w:gz') as tar:
    tar.add(os.path.join(OSS_FUZZ_ROOT, project_rel_path),
            arcname=project_rel_path)


def run_build(  # pylint: disable=too-many-arguments, too-many-locals
    oss_fuzz_project,
    steps,
    credentials,
    cloud_project,
    timeout,
    body_overrides=None,
    tags=None,
    use_build_pool=True,
    experiment=False):
  """Runs the build."""

  build_body = get_build_body(steps,
                              timeout,
                              body_overrides,
                              tags,
                              use_build_pool=use_build_pool,
                              experiment=experiment)
  if experiment:
    with tempfile.NamedTemporaryFile(suffix='source.tgz') as tgz_file:
      # Archive the necessary files for the build.
      _tgz_local_build(oss_fuzz_project, tgz_file.name)
      gcs_client = storage.Client()
      # This is the automatically created Cloud Build bucket for Cloud Build.
      bucket_name = gcs_client.project + '_cloudbuild'
      bucket = gcs_client.bucket(bucket_name)
      blob_name = f'source/{str(uuid.uuid4())}.tgz'
      blob = bucket.blob(blob_name)
      logging.info(f'Uploading project to {bucket_name}/{blob_name}')
      blob.upload_from_filename(tgz_file.name)

      build_body['source'] = {
          'storageSource': {
              'bucket': bucket_name,
              'object': blob_name,
          }
      }

  cloudbuild = cloud_build('cloudbuild',
                           'v1',
                           credentials=credentials,
                           cache_discovery=False,
                           client_options=REGIONAL_CLIENT_OPTIONS)

  build_info = cloudbuild.projects().builds().create(projectId=cloud_project,
                                                     body=build_body).execute()

  build_id = build_info['metadata']['build']['id']

  logging.info(f'{oss_fuzz_project}. logs: {get_logs_url(build_id)}. '
               f'GCB page: {get_gcb_url(build_id, cloud_project)}')
  return build_id


def wait_for_build(build_id, credentials, cloud_project):
  """Wait for a GCB build."""
  cloudbuild = cloud_build('cloudbuild',
                           'v1',
                           credentials=credentials,
                           cache_discovery=False,
                           client_options=REGIONAL_CLIENT_OPTIONS)

  while True:
    try:
      status = cloudbuild.projects().builds().get(projectId=cloud_project,
                                                  id=build_id).execute()
      if status.get('status') in ('SUCCESS', 'FAILURE', 'TIMEOUT',
                                  'INTERNAL_ERROR', 'EXPIRED', 'CANCELLED'):
        # Build done.
        return
    except (googleapiclient.errors.HttpError, BrokenPipeError):
      pass

    time.sleep(15)  # Avoid rate limiting.


def cancel_build(build_id, credentials, cloud_project):
  """Cancel a GCB build"""
  cloudbuild = cloud_build('cloudbuild',
                           'v1',
                           credentials=credentials,
                           cache_discovery=False,
                           client_options=REGIONAL_CLIENT_OPTIONS)
  cloudbuild.projects().builds().cancel(projectId=cloud_project,
                                        id=build_id).execute()
