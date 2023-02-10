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

import sys
import atheris
with atheris.instrument_imports():
    import google.cloud.iam_credentials_v1.services.iam_credentials as iam

def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    iam.IAMCredentialsClient.service_account_path(
        fdp.ConsumeString(100),
        fdp.ConsumeString(100)
    )
    iam.IAMCredentialsClient.parse_service_account_path(fdp.ConsumeString(100))
    iam.IAMCredentialsClient.parse_service_account_path(
        "projects/%s/serviceAccounts/%s"%(
            fdp.ConsumeString(100),
            fdp.ConsumeString(100)
        )
    )

    iam.IAMCredentialsClient.common_billing_account_path(fdp.ConsumeString(100))
    iam.IAMCredentialsClient.parse_common_billing_account_path(fdp.ConsumeString(100))
    iam.IAMCredentialsClient.parse_common_billing_account_path(
        "billingAccounts/%s/"%fdp.ConsumeString(100)
    )

    iam.IAMCredentialsClient.common_folder_path(fdp.ConsumeString(100))
    iam.IAMCredentialsClient.parse_common_folder_path(fdp.ConsumeString(100))
    iam.IAMCredentialsClient.parse_common_folder_path(
        "folders/%s/"%fdp.ConsumeString(100)
    )

    iam.IAMCredentialsClient.common_organization_path(fdp.ConsumeString(100))
    iam.IAMCredentialsClient.parse_common_organization_path(fdp.ConsumeString(100))
    iam.IAMCredentialsClient.parse_common_organization_path(
        "organizations/%s/"%fdp.ConsumeString(100)
    )

    iam.IAMCredentialsClient.common_project_path(fdp.ConsumeString(100))
    iam.IAMCredentialsClient.parse_common_project_path(fdp.ConsumeString(100))
    iam.IAMCredentialsClient.parse_common_project_path(
        "projects/%s/"%fdp.ConsumeString(100)
    )

    iam.IAMCredentialsClient.common_location_path(
        fdp.ConsumeString(100),
        fdp.ConsumeString(100)
    )
    iam.IAMCredentialsClient.parse_common_location_path(fdp.ConsumeString(100))
    iam.IAMCredentialsClient.parse_common_location_path(
        "projects/%s/locations/%s"%(
            fdp.ConsumeString(100),
            fdp.ConsumeString(100)
        )
    )

def main():
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
