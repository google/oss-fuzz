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
from c7n.resources import health, kafka, sagemaker, ebs, emr, awslambda, securityhub, cw, ec2

def TestOneInput(data):
    """Fuzz encode and decode"""
    fdp = atheris.FuzzedDataProvider(data)
    choice = fdp.ConsumeIntInRange(1, 11)
    data = _generate_random_dict(fdp)

    try:
        if choice == 1:
            object = health.QueryFilter(data)
        elif choice == 2:
            object = kafka.SetMonitoring(data = data)
        elif choice == 3:
            object = sagemaker.QueryFilter(data)
        elif choice == 4:
            object = ebs.CopySnapshot(data = data)
        elif choice == 5:
            object = emr.QueryFilter(data = data)
        elif choice == 6:
            object = awslambda.SetConcurrency(data = data)
        elif choice == 7:
            object = securityhub.SetConcurrency(data = data)
        elif choice == 8:
            object = cw.EncryptLogGroup(data = data)
        elif choice == 9:
            object = ec2.DisableApiStop(data = data)
        elif choice == 10:
            object = ec2.Snapshot(data = data)
        elif choice == 11:
            object = ec2.QueryFilter(data = data)

        object.validate()
    except exceptions.PolicyValidationError:
        pass


def _generate_random_dict(fdp):
    map = dict()

    for count in range(fdp.ConsumeIntInRange(1, 5)):
        map[fdp.ConsumeUnicodeNoSurrogates(128)] = fdp.ConsumeUnicodeNoSurrogates(128)

    return map


def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
