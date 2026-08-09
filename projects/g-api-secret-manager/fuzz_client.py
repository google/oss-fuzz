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
import atheris
import mock

from google.auth import credentials
from google.cloud.secretmanager_v1beta1.services.secret_manager_service import (
    SecretManagerServiceAsyncClient,
    SecretManagerServiceClient,
    pagers,
    transports,
)
from google.cloud.secretmanager_v1beta1.types import resources, service

def test_add_secret_version(client, fdp):
    """Calls add_secret_version on the client with data from the fuzzer"""

    # Create the input.
    if fdp.ConsumeBool():
        request = service.AddSecretVersionRequest()
        try:
            request.parent = fdp.ConsumeUnicodeNoSurrogates(20)
        except:
            request.parent = None
    else:
        request = {}

    parent = None
    payload = None
    if fdp.ConsumeBool():
        parent = fdp.ConsumeUnicodeNoSurrogates(10)
        request = None
        payload = resources.SecretPayload()
        payload.data = fdp.ConsumeBytes(10)


    # Mock call within the gRPC stub and fake the request.
    with mock.patch.object(
        type(client.transport.add_secret_version), "__call__"
    ) as call:
        # Create return value for the call.
        call.return_value = resources.SecretVersion(
            name="name_value",
            state=resources.SecretVersion.State.ENABLED,
        )

        response = client.add_secret_version(
            request = request,
            parent = parent,
            payload = payload
        )


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    # Create a client we can call.
    client = SecretManagerServiceClient(
        credentials=credentials.AnonymousCredentials(),
        transport="grpc",
    )
    
    test_add_secret_version(client, fdp)


def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
