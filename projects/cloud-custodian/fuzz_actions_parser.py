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
from botocore.exceptions import ProfileNotFound

with atheris.instrument_imports():
    from c7n import policy as c7n_policy
    from c7n import exceptions, manager

    from c7n.filters import FilterRegistry
    from c7n.actions import ActionRegistry

    from c7n.resources import aws, rdsparamgroup, elasticache, ec2
    from c7n.resources import emr, account, apigw, elb, s3, glue
    from c7n.resources import appelb

def TestOneInput(data):
    """Fuzz encode and decode"""
    registry_type = [
        'c7n.data', 'rds-param-group', 'elasticache', 'ec2', 'emr',
        'aws.account', 'rest-account', 'elb', 's3', 'iac', 'rds',
        'glue-catalog', 'app-elb-target-group'
    ]
    provider = 'aws'

    fdp = atheris.FuzzedDataProvider(data)

    option = FuzzOption(fdp)
    data = _generate_random_dict(fdp)
    manager_data = _generate_random_dict(fdp)
    type = fdp.PickValueInList(registry_type)
    action_registry = ActionRegistry("%s.actions" % type)
    filter_registry = FilterRegistry("%s.filters" % type)
    resource_manager = manager.ResourceManager(FuzzContext(provider, option), manager_data)
    resource_manager.action_registry = action_registry
    resource_manager.filter_registry = filter_registry
    resource_manager.type = type
    resources = manager.resources

    try:
        action_registry.parse(data, resource_manager)
    except (exceptions.PolicyValidationError, ProfileNotFound):
        pass
    except (KeyError, TypeError):
        pass


def _generate_random_dict(fdp):
    map = dict()

    for count in range(fdp.ConsumeIntInRange(1, 100)):
        map[fdp.ConsumeUnicodeNoSurrogates(1024)] = fdp.ConsumeUnicodeNoSurrogates(1024)

    map["name"] = fdp.ConsumeUnicodeNoSurrogates(1024)

    return map


def initializeProviders():
    aws.AWS()


def main():
    initializeProviders()

    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()


class FuzzContext:
    def __init__(self, name, option):
        self.options = None
        self.session_factory = c7n_policy.get_session_factory(name, option)
        self.policy = FuzzPolicy(name)


class FuzzPolicy:
    def __init__(self, provider_name):
        self.provider_name = provider_name
        self.name = "FuzzName"


class FuzzOption:
    def __init__(self, fdp):
        self.region = fdp.ConsumeUnicodeNoSurrogates(1024)
        self.profile = fdp.ConsumeUnicodeNoSurrogates(1024)
        self.assume_role = fdp.ConsumeUnicodeNoSurrogates(1024)
        self.external_id = fdp.ConsumeUnicodeNoSurrogates(1024)


if __name__ == "__main__":
    main()
