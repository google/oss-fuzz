#!/usr/bin/python3
# Copyright 2023 Google LLC
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

from c7n import exceptions
from c7n.resources import ec2, aws, health, sagemaker, emr

def TestOneInput(data):
    """Fuzz encode and decode"""
    fdp = atheris.FuzzedDataProvider(data)
    choice = fdp.ConsumeIntInRange(1, 5)

    try:
        if choice == 1:
            ec2.QueryFilter.parse(fdp.ConsumeUnicodeNoSurrogates(1024))
        elif choice == 2:
            aws.Arn.parse(fdp.ConsumeUnicodeNoSurrogates(1024))
        elif choice == 3:
            health.QueryFilter.parse(fdp.ConsumeUnicodeNoSurrogates(1024))
        elif choice == 4:
            sagemaker.QueryFilter.parse(fdp.ConsumeUnicodeNoSurrogates(1024))
        elif choice == 5:
            emr.QueryFilter.parse(fdp.ConsumeUnicodeNoSurrogates(1024))
    except exceptions.PolicyValidationError:
        pass
    except ValueError as e:
        if "Invalid structure" not in str(e):
            raise e


def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
