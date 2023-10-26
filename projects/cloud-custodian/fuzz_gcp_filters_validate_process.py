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
from google.auth.exceptions import DefaultCredentialsError

with atheris.instrument_imports():
    from c7n import policy as c7n_policy
    from c7n import exceptions, manager, data

    from c7n.filters import FilterRegistry, FilterValidationError
    from c7n.actions import ActionRegistry

    from c7n_gcp import provider

    from c7n_gcp.filters import labels, recommender, metrics, alerts
    from c7n_gcp.filters import sccfindings, timerange, iampolicy

    from c7n_gcp.resources import iam, dns, armor, build, secret
    from c7n_gcp.resources import pubsub, logging, network, mlengine
    from c7n_gcp.resources import bigquery, cloudrun, appengine
    from c7n_gcp.resources import loadbalancer, sql, service, gke
    from c7n_gcp.resources import bigtable, memstore, kms, datafusion
    from c7n_gcp.resources import cloudbilling, function, spanner
    from c7n_gcp.resources import resourcemanager, source, osconfig
    from c7n_gcp.resources import dataproc, notebook, artifactregistry
    from c7n_gcp.resources import compute, storage, deploymentmanager
    from c7n_gcp.resources import dataflow


def TestOneInput(data):
    """Fuzz tools/c7n_gcp"""
    object = None

    fdp = atheris.FuzzedDataProvider(data)
    choice = fdp.ConsumeIntInRange(1, 7)

    option = FuzzOption(fdp)
    data = _generate_random_dict(fdp)
    event = _generate_random_dict(fdp)
    manager_data = _generate_random_dict(fdp)

    type = fdp.ConsumeUnicodeNoSurrogates(1024)
    action_registry = ActionRegistry("%s.actions" % type)
    filter_registry = FilterRegistry("%s.filters" % type)

    resource_manager = manager.ResourceManager(FuzzContext("gcp", option), manager_data)
    resource_manager.action_registry = action_registry
    resource_manager.filter_registry = filter_registry
    resource_manager.type = type
    resources = manager.resources

    try:
        if choice == 1:
            object = labels.LabelActionFilter(data, resource_manager)
            object.parse(fdp.ConsumeUnicodeNoSurrogates(1024))
            object.validate()
        elif choice == 2:
            object = recommender.RecommenderFilter(data, resource_manager)
            object.validate()
        elif choice == 3:
            object = metrics.GCPMetricsFilter(data, resource_manager)
            object.validate()
        elif choice == 4:
            object = sccfindings.SecurityComandCenterFindingsFilter(data, resource_manager)
        elif choice == 5:
            object = timerange.TimeRangeFilter(data, resource_manager)
        elif choice == 6:
            object = iampolicy.IamPolicyFilter(data, resource_manager)
        elif choice == 7:
            object = alerts.AlertsFilter(data, resource_manager)

        if object:
            object.process(resources, event)
    except (
        exceptions.PolicyValidationError,
        DefaultCredentialsError,
        FilterValidationError):
        pass
    except ValueError as e:
        if "Filter requires resource expression" not in str(e) and "not enough values to unpack" not in str(e):
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
    provider.GoogleCloud()


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
        self.account_id = fdp.ConsumeUnicodeNoSurrogates(1024)


class FuzzConfig:
    def __init__(self, fdp):
        self.account_id = fdp.ConsumeUnicodeNoSurrogates(1024)
        self.region = fdp.ConsumeUnicodeNoSurrogates(1024)


if __name__ == "__main__":
    main()
