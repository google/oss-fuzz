#!/usr/bin/python3
# Copyright 2022 Google LLC
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

import os
import sys
import mock
import atheris

from google.auth import credentials as ga_credentials
from google.cloud.tasks_v2.services.cloud_tasks import CloudTasksClient
from google.cloud.tasks_v2.types import queue
from google.cloud.tasks_v2.types import cloudtasks


def get_request_queue(fdp, client):
    request = cloudtasks.GetQueueRequest()
    request.name = fdp.ConsumeUnicodeNoSurrogates(20)
    with mock.patch.object(type(client.transport.get_queue), "__call__") as call:
        call.return_value = queue.Queue()
        client.get_queue(request)


def update_queue(fdp, client):
    request = cloudtasks.UpdateQueueRequest()
    with mock.patch.object(type(client.transport.update_queue), "__call__") as call:
        call.return_value = queue.Queue(
            name=fdp.ConsumeUnicodeNoSurrogates(20),
            state=queue.Queue.State.RUNNING,
        )
        response = client.update_queue(request)


def delete_queue(fdp, client):
    request = cloudtasks.DeleteQueueRequest()
    request.name = fdp.ConsumeUnicodeNoSurrogates(20)
    with mock.patch.object(type(client.transport.delete_queue), "__call__") as call:
        call.return_value = None
        response = client.delete_queue(request)


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    client = CloudTasksClient(
        credentials=ga_credentials.AnonymousCredentials(),
    )

    api_targets = [
        get_request_queue,
        update_queue,
        delete_queue
    ]
    num_of_calls = fdp.ConsumeIntInRange(1, 10)
    for i in range(num_of_calls):
        target = api_targets[fdp.ConsumeIntInRange(0, len(api_targets)-1)]
        target(fdp, client)


def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
