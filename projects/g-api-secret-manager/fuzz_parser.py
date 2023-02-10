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

from google.cloud.secretmanager_v1beta1.services.secret_manager_service import (
    SecretManagerServiceClient,
)

def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    SecretManagerServiceClient.parse_secret_path(fdp.ConsumeString(sys.maxsize))
    SecretManagerServiceClient.parse_common_location_path(fdp.ConsumeString(sys.maxsize))
    SecretManagerServiceClient.parse_common_project_path(fdp.ConsumeString(sys.maxsize))
    SecretManagerServiceClient.parse_common_organization_path(fdp.ConsumeString(sys.maxsize))
    SecretManagerServiceClient.parse_common_folder_path(fdp.ConsumeString(sys.maxsize))
    SecretManagerServiceClient.parse_common_billing_account_path(fdp.ConsumeString(sys.maxsize))


def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
