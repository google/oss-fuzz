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
from botocore.exceptions import ClientError, ProfileNotFound

with atheris.instrument_imports():
    from c7n import policy as c7n_policy
    from c7n import exceptions, data, query, manager

    from c7n.filters import FilterRegistry
    from c7n.actions import ActionRegistry
    from c7n.resources.aws import AWS

    from c7n.resources import ml, sar, s3control, ec2, ebs
    from c7n.resources import batch, mq, route53, securityhub
    from c7n.resources import vpc, shield, iam, sfn, cloudtrail
    from c7n.resources import code, appflow, awslambda, emr, ami
    from c7n.resources import secretsmanager, airflow, account
    from c7n.resources import cloudfront, elasticsearch

def TestOneInput(data):
    """Fuzz validate functions in resources package"""
    registry_type = [
        'c7n.data', 'rds-param-group', 'elasticache', 'ec2', 'emr',
        'aws.account', 'rest-account', 'elb', 's3', 'iac', 'rds',
        'glue-catalog', 'app-elb-target-group'
    ]
    provider = 'aws'
    object = None
    event = None
    resources_object = None

    fdp = atheris.FuzzedDataProvider(data)
    choice = fdp.ConsumeIntInRange(1, 58)

    option = FuzzOption(fdp)
    data = _generate_random_dict(fdp)
    manager_data = _generate_random_dict(fdp)

    type = fdp.PickValueInList(registry_type)
    action_registry = ActionRegistry("%s.actions" % type)
    filter_registry = FilterRegistry("%s.filters" % type)

    context = FuzzContext(provider, option)
    resource_manager = query.QueryResourceManager(context, manager_data)
    resource_manager.action_registry = action_registry
    resource_manager.filter_registry = filter_registry
    resource_manager.type = type
    resource_manager.config = FuzzConfig(fdp)
    resources = manager.resources

    initializeResources(context, manager_data)

    try:
        if choice == 1:
            object = ml.DeleteMLModel(data = data, manager = resource_manager)
        elif choice == 2:
            object = sar.Delete(data = data, manager = resource_manager)
        elif choice == 3:
            object = sar.CrossAccount(data = data, manager = resource_manager)
        elif choice == 4:
            object = s3control.AccessPointCrossAccount(data = data, manager = resource_manager)
        elif choice == 5:
            object = s3control.Delete(data = data, manager = resource_manager)
        elif choice == 6:
            object = ec2.MonitorInstances(data = data, manager = resource_manager)
        elif choice == 7:
            resources_object = batch.UpdateComputeEnvironment(data = data, manager = resource_manager)
        elif choice == 8:
            resources_object = batch.DeleteComputeEnvironment(data = data, manager = resource_manager)
        elif choice == 9:
            resources_object = batch.DefinitionDeregister(data = data, manager = resource_manager)
        elif choice == 10:
            resources_object = mq.Delete(data = data, manager = resource_manager)
        elif choice == 11:
            resources_object = route53.SetQueryLogging(data = data, manager = resource_manager)
            resources_object.validate()
        elif choice == 12:
            resources_object = route53.IsQueryLoggingEnabled(data = data, manager = resource_manager)
            event = _generate_random_dict(fdp)
        elif choice == 13:
            resources_object = route53.ResolverQueryLogConfigAssociate(data = data, manager = resource_manager)
        elif choice == 14:
            resources_object = route53.ReadinessCheckCrossAccount(data = data, manager = resource_manager)
            event = _generate_random_dict(fdp)
        elif choice == 15:
            resources_object = securityhub.SecurityHubFindingFilter(data = data, manager = resource_manager)
            event = _generate_random_dict(fdp)
            resources_object.validate()
        elif choice == 16:
            resources_object = securityhub.PostFinding(data = data, manager = resource_manager)
            event = _generate_random_dict(fdp)
            resources_object.validate()
        elif choice == 17:
            resources_object = cloudfront.IsWafEnabled(data = data, manager = resource_manager)
            event = _generate_random_dict(fdp)
        elif choice == 18:
            resources_object = vpc.ModifyVpc(data = data, manager = resource_manager)
        elif choice == 19:
            resources_object = vpc.DeleteVpc(data = data, manager = resource_manager)
        elif choice == 20:
            resources_object = shield.SetShieldProtection(data = data, manager = resource_manager)
        elif choice == 21:
            resources_object = iam.SetBoundary(data = data, manager = resource_manager)
            resources_object.validate()
        elif choice == 22:
            resources_object = iam.CertificateDelete(data = data, manager = resource_manager)
        elif choice == 23:
            resources_object = iam.SetPolicy(data = data, manager = resource_manager)
            resources_object.validate()
        elif choice == 24:
            resources_object = iam.RoleDelete(data = data, manager = resource_manager)
        elif choice == 25:
            resources_object = sfn.InvokeStepFunction(data = data, manager = resource_manager)
        elif choice == 26:
            resources_object = cloudtrail.Status(data = data, manager = resource_manager)
            event = _generate_random_dict(fdp)
        elif choice == 27:
            resources_object = cloudtrail.EventSelectors(data = data, manager = resource_manager)
            event = _generate_random_dict(fdp)
        elif choice == 28:
            resources_object = cloudtrail.UpdateTrail(data = data, manager = resource_manager)
            resources_object.validate()
        elif choice == 29:
            resources_object = cloudtrail.DeleteTrail(data = data, manager = resource_manager)
        elif choice == 30:
            resources_object = code.DeleteApplication(data = data, manager = resource_manager)
        elif choice == 31:
            resources_object = code.DeleteDeploymentGroup(data = data, manager = resource_manager)
        elif choice == 32:
            resources_object = appflow.DeleteAppFlowResource(data = data, manager = resource_manager)
        elif choice == 33:
            resources_object = awslambda.LambdaEnableXrayTracing(data = data, manager = resource_manager)
        elif choice == 34:
            resources_object = awslambda.LambdaEventSource(data = data, manager = resource_manager)
            event = _generate_random_dict(fdp)
        elif choice == 35:
            resources_object = awslambda.LambdaCrossAccountAccessFilter(data = data, manager = resource_manager)
            event = _generate_random_dict(fdp)
        elif choice == 36:
            resources_object = awslambda.VersionTrim(data = data, manager = resource_manager)
        elif choice == 37:
            resources_object = awslambda.RemovePolicyStatement(data = data, manager = resource_manager)
        elif choice == 38:
            resources_object = awslambda.LayerCrossAccount(data = data, manager = resource_manager)
            event = _generate_random_dict(fdp)
        elif choice == 39:
            resources_object = awslambda.LayerRemovePermissions(data = data, manager = resource_manager)
        elif choice == 40:
            resources_object = awslambda.DeleteLayerVersion(data = data, manager = resource_manager)
        elif choice == 41:
            resources_object = emr.EMRSecurityConfigurationFilter(data = data, manager = resource_manager)
            event = _generate_random_dict(fdp)
        elif choice == 42:
            resources_object = emr.DeleteEMRSecurityConfiguration(data = data, manager = resource_manager)
        elif choice == 43:
            resources_object = emr.EMRServerlessDelete(data = data, manager = resource_manager)
        elif choice == 44:
            resources_object = ami.AmiCrossAccountFilter(data = data, manager = resource_manager)
            event = _generate_random_dict(fdp)
        elif choice == 45:
            resources_object = secretsmanager.CrossAccountAccessFilter(data = data, manager = resource_manager)
            event = _generate_random_dict(fdp)
        elif choice == 46:
            resources_object = secretsmanager.HasStatementFilter(data = data, manager = resource_manager)
            event = _generate_random_dict(fdp)
        elif choice == 47:
            resources_object = airflow.UpdateApacheAirflowEnvironment(data = data, manager = resource_manager)
        elif choice == 48:
            resources_object = airflow.DeleteApacheAirflowEnvironment(data = data, manager = resource_manager)
        elif choice == 49:
            resources_object = account.AccountCredentialReport(data = data, manager = resource_manager)
            event = _generate_random_dict(fdp)
        elif choice == 50:
            resources_object = account.AccountOrganization(data = data, manager = resource_manager)
            event = _generate_random_dict(fdp)
        elif choice == 51:
            resources_object = account.MacieEnabled(data = data, manager = resource_manager)
            event = _generate_random_dict(fdp)
        elif choice == 52:
            resources_object = account.CloudTrailEnabled(data = data, manager = resource_manager)
            event = _generate_random_dict(fdp)
        elif choice == 53:
            resources_object = account.ConfigEnabled(data = data, manager = resource_manager)
            event = _generate_random_dict(fdp)
        elif choice == 54:
            resources_object = account.IAMSummary(data = data, manager = resource_manager)
            event = _generate_random_dict(fdp)
        elif choice == 55:
            resources_object = account.AccessAnalyzer(data = data, manager = resource_manager)
            event = _generate_random_dict(fdp)
        elif choice == 56:
            resources_object = account.AccountPasswordPolicy(data = data, manager = resource_manager)
            event = _generate_random_dict(fdp)
        elif choice == 57:
            resources_object = elasticsearch.ElasticSearchCrossAccountAccessFilter(data = data, manager = resource_manager)
            event = _generate_random_dict(fdp)
        elif choice == 58:
            resources_object = elasticsearch.ElasticSearchCrossClusterFilter(data = data, manager = resource_manager)
            event = _generate_random_dict(fdp)

        if object:
            object.process(data)
        if resources_object:
            if event:
                resources_object.process(resources, event)
            else:
                resources_object.process(resources)
    except (
        ValueError, ClientError, ProfileNotFound,
        KeyError, TypeError,
        exceptions.PolicyValidationError):
        pass
    except AttributeError as e:
        if "object has no attribute" not in str(e):
            raise e


def _generate_random_dict(fdp):
    map = dict()

    for count in range(fdp.ConsumeIntInRange(1, 100)):
        map[fdp.ConsumeUnicodeNoSurrogates(1024)] = fdp.ConsumeUnicodeNoSurrogates(1024)

    map["name"] = fdp.ConsumeUnicodeNoSurrogates(1024)

    return map


def initializeProviders():
    AWS()


def initializeResources(ctx, data):
    ebs.EBS(ctx, data)
    ebs.Snapshot(ctx, data)
    ami.AMI(ctx, data)
    route53.ResolverQueryLogConfig(ctx, data)
    emr.EMRSecurityConfiguration(ctx, data)


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

