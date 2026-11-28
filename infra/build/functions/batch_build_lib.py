# Copyright 2024 Google LLC
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
import base64
import os
import time
import uuid
import json


import six.moves.urllib.parse as urlparse

from google.cloud import batch_v1 as batch
from google.cloud import storage
from oauth2client import service_account as service_account_lib
import yaml

MACHINE_TYPE = 'e2-standard-4'
SERVICE_ACCOUNT = '608308004811@cloudbuild.gserviceaccount.com'

BUILD_TIMEOUT= 20*60


DIRECTORY = os.path.dirname(__file__)
STARTUP_SCRIPT = os.path.join(DIRECTORY, 'cloud_build_emulator.py')
# Controls how many containers (ClusterFuzz tasks) can run on a single VM.
# THIS SHOULD BE 1 OR THERE WILL BE SECURITY PROBLEMS.
TASK_COUNT_PER_NODE = 1

def get_job_name():
  return 'j-' + str(uuid.uuid4()).lower()


BATCH_BUILD_INPUT_BUCKET = 'batch-build-input'


def upload_build_config(job_name, build_config):
  gcs_client = storage.Client()
  bucket = gcs_client.bucket(BATCH_BUILD_INPUT_BUCKET)
  yaml_filename = job_name + '.json'
  blob = bucket.blob(yaml_filename)
  blob.upload_from_string(json.dumps(build_config))
  return get_signed_url(f'/{BATCH_BUILD_INPUT_BUCKET}/{yaml_filename}', method='GET')


def get_signed_url(path, method='PUT', content_type=''):
  """Returns signed url."""
  timestamp = int(time.time() + BUILD_TIMEOUT)
  blob = f'{method}\n\n{content_type}\n{timestamp}\n{path}'

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

  values = {
      'GoogleAccessId': client_id,
      'Expires': timestamp,
      'Signature': signature,
  }
  return f'https://storage.googleapis.com{path}?{urlparse.urlencode(values)}'


def run_build(
    build_body,
    cloud_project,
    timeout, credentials):
    job_name = get_job_name()
    input_download_url = upload_build_config(job_name, build_body)
    runnable = batch.Runnable()
    with open(STARTUP_SCRIPT) as fp:
        script_text = fp.read()
    runnable.script = batch.Runnable.Script(path='/opt/cloud_build_emulator.py', text=script_text)
    task_spec = batch.TaskSpec()
    task_spec.runnables = [runnable]
    task_spec.max_run_duration = f'{20 * 60}s'
    task_spec.max_retry_count = 1
    disk = batch.AllocationPolicy.Disk()
    disk.image = 'batch-debian'
    disk.size_gb = '60'
    disk.type = 'pd-standard'
    instance_policy = batch.AllocationPolicy.InstancePolicy()
    instance_policy.boot_disk = disk
    instance_policy.machine_type = MACHINE_TYPE
    instances = batch.AllocationPolicy.InstancePolicyOrTemplate()
    instances.policy = instance_policy
    network_interface = batch.AllocationPolicy.NetworkInterface()
    network_interfaces = [network_interface]
    network_policy = batch.AllocationPolicy.NetworkPolicy()
    network_policy.network_interfaces = network_interfaces
    allocation_policy = batch.AllocationPolicy()
    allocation_policy.instances = [instances]
    allocation_policy.network = network_policy
    task_group = batch.TaskGroup()
    task_group.task_count = 1 # !!!
    task_group.task_environments = [
        batch.Environment(variables={'INPUT_DOWNLOAD_URL': input_download_url})
    ]
    task_group.task_spec = task_spec
    job = batch.Job()
    job.task_groups = [task_group]
    job.allocation_policy = allocation_policy
    job.logs_policy = batch.LogsPolicy()
    job.logs_policy.destination = batch.LogsPolicy.Destination.CLOUD_LOGGING
    create_request = batch.CreateJobRequest()
    create_request.job = job    
    create_request.job_id = job_name
    # The job's parent is the region in which the job will run.
    create_request.parent = f'projects/oss-fuzz/locations/us-central1'
    del os.environ['GOOGLE_APPLICATION_CREDENTIALS']
    return batch.BatchServiceClient().create_job(create_request)
