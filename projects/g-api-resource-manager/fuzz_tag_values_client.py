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
"""Fuzzer for google/cloud/resourcemanager_v3/services/tag_values/client.py"""

import os
import sys
import atheris

import mock

from google.auth import credentials as ga_credentials
from google.longrunning import operations_pb2
from google.iam.v1 import iam_policy_pb2
from google.iam.v1 import policy_pb2 
from google.cloud.resourcemanager_v3.services.tag_values import (
    TagValuesAsyncClient,
    TagValuesClient,
    pagers,
    transports,
)
from google.cloud.resourcemanager_v3.types import tag_values


def test_get_tag_value(fdp, client):
    if fdp.ConsumeBool():
        request = tag_values.GetTagValueRequest()
    else:
        request = dict()

    with mock.patch.object(type(client.transport.get_tag_value), "__call__") as call:
        call.return_value = tag_values.TagValue(
            name=fdp.ConsumeUnicodeNoSurrogates(10),
            parent=fdp.ConsumeUnicodeNoSurrogates(10),
            short_name=fdp.ConsumeUnicodeNoSurrogates(10),
            namespaced_name=fdp.ConsumeUnicodeNoSurrogates(10),
            description=fdp.ConsumeUnicodeNoSurrogates(10),
            etag=fdp.ConsumeUnicodeNoSurrogates(10),
        )

        response = client.get_tag_value(request)


def test_create_tag_value(fdp, client):
    if fdp.ConsumeBool():
        request = tag_values.CreateTagValueRequest()
    else:
        request = dict()

    with mock.patch.object(type(client.transport.create_tag_value), "__call__") as call:
        call.return_value = operations_pb2.Operation(name=fdp.ConsumeUnicodeNoSurrogates(20))
        response = client.create_tag_value(request)

def test_update_tag_value(fdp, client):
    if fdp.ConsumeBool():
        request = tag_values.UpdateTagValueRequest()
    else:
        request = dict()

    with mock.patch.object(type(client.transport.update_tag_value), "__call__") as call:
        call.return_value = operations_pb2.Operation(name=fdp.ConsumeUnicodeNoSurrogates(20))
        response = client.update_tag_value(request)


def test_delete_tag_value(fdp, client):
    if fdp.ConsumeBool():
        request = tag_values.DeleteTagValueRequest()
    else:
        request = dict()

    with mock.patch.object(type(client.transport.delete_tag_value), "__call__") as call:
        call.return_value = operations_pb2.Operation(name="operations/spam")
        response = client.delete_tag_value(request)

def test_get_iam_policy(fdp, client):
    if fdp.ConsumeBool():
        request = iam_policy_pb2.GetIamPolicyRequest()
    else:
        request = dict()

    with mock.patch.object(type(client.transport.get_iam_policy), "__call__") as call:
        call.return_value = policy_pb2.Policy(
            version=774,
            etag=fdp.ConsumeBytes(20),
        )
        response = client.get_iam_policy(request)

def test_set_iam_policy(fdp, client):
    if fdp.ConsumeBool():
        request = iam_policy_pb2.SetIamPolicyRequest()
    else:
        request = dict()

    with mock.patch.object(type(client.transport.set_iam_policy), "__call__") as call:
        call.return_value = policy_pb2.Policy(
            version=774,
            etag=fdp.ConsumeBytes(20),
        )
        response = client.set_iam_policy(request)

def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    # Create our client
    client = TagValuesClient(
        credentials=ga_credentials.AnonymousCredentials(),
        transport="grpc",
    )

    # Call a set of operations on the client. Using mocked responses.
    operations = [
        test_get_tag_value,
        test_create_tag_value,
        test_update_tag_value,
        test_delete_tag_value,
        test_get_iam_policy,
        test_set_iam_policy
    ]
    number_of_calls = 20
    for i in range(number_of_calls):
        target = operations[fdp.ConsumeIntInRange(0, len(operations)-1)]
        target(fdp, client)

def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
