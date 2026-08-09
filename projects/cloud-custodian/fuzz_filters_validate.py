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
    from c7n import exceptions, manager, data

    from c7n.filters import FilterRegistry
    from c7n.actions import ActionRegistry

    from c7n.filters import multiattr, missing, metrics
    from c7n.filters import offhours, vpc, revisions

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
    object = None

    fdp = atheris.FuzzedDataProvider(data)
    choice = fdp.ConsumeIntInRange(1, 10)

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
        if choice == 1:
            object = multiattr.MultiAttrFilter(data, resource_manager)
        elif choice == 2:
            data['policy'] = resource_manager.ctx.policy
            object = missing.Missing(data, resource_manager)
        elif choice == 3:
            object = metrics.MetricsFilter(data, resource_manager)
        elif choice == 4:
            object = offhours.OnHour(data, resource_manager)
        elif choice == 5:
            object = offhours.OffHour(data, resource_manager)
        elif choice == 6:
            object = vpc.SecurityGroupFilter(data, resource_manager)
        elif choice == 7:
            object = vpc.SubnetFilter(data, resource_manager)
        elif choice == 8:
            object = vpc.VpcFilter(data, resource_manager)
        elif choice == 9:
            object = vpc.NetworkLocation(data, resource_manager)
        elif choice == 10:
            object = revisions.Diff(data, resource_manager)

        if object:
            object.validate()
    except (exceptions.PolicyValidationError, ProfileNotFound):
        pass
    except ValueError as e:
        if "Filter requires resource expression" not in str(e):
            raise e
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
        self.tracer = FuzzTracer()
        self.execution_id = "id"
        self.start_time = "1234567890"


class FuzzPolicy:
    def __init__(self, provider_name):
        self.provider_name = provider_name
        self.name = "FuzzName"


class FuzzTracer:
    def subsegment(type):
        return True


class FuzzOption:
    def __init__(self, fdp):
        self.region = fdp.ConsumeUnicodeNoSurrogates(1024)
        self.profile = fdp.ConsumeUnicodeNoSurrogates(1024)
        self.assume_role = fdp.ConsumeUnicodeNoSurrogates(1024)
        self.external_id = fdp.ConsumeUnicodeNoSurrogates(1024)


class FuzzConfig:
    def __init__(self, fdp):
        self.account_id = fdp.ConsumeUnicodeNoSurrogates(1024)
        self.region = fdp.ConsumeUnicodeNoSurrogates(1024)


if __name__ == "__main__":
    main()
