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

# with atheris.instrument_imports(): # For local testing
from c7n import exceptions, manager
from c7n.resources import health, kafka, sagemaker, ebs, emr, route53
from c7n.resources import awslambda, cw, ec2, ecr, servicecatalog, asg
from c7n.resources import secretsmanager, account, redshift, eks, glue
from c7n.resources import securityhub, cloudtrail, ssm, rds, efs, vpc
from c7n.resources import rdscluster, iam, ami, appelb, s3, cloudfront

def TestOneInput(data):
    """Fuzz validate functions in resources package"""
    fdp = atheris.FuzzedDataProvider(data)
    choice = fdp.ConsumeIntInRange(1, 56)
    object = None

    data = _generate_random_dict(fdp)
    manager_data = _generate_random_dict(fdp)
    resource_manager = manager.ResourceManager(FuzzContext(FuzzPolicy), manager_data)

    try:
        if choice == 1:
            object = health.QueryFilter(data)
        elif choice == 2:
            object = kafka.SetMonitoring(data = data, manager = resource_manager)
        elif choice == 3:
            object = sagemaker.QueryFilter(data)
        elif choice == 4:
            object = ebs.CopySnapshot(data = data, manager = resource_manager)
        elif choice == 5:
            object = emr.QueryFilter(data)
        elif choice == 6:
            object = awslambda.SetConcurrency(data = data, manager = resource_manager)
        elif choice == 7:
            object = cw.EncryptLogGroup(data = data, manager = resource_manager)
        elif choice == 8:
            object = ec2.DisableApiStop(data = data, manager = resource_manager)
        elif choice == 9:
            object = ec2.Snapshot(data = data, manager = resource_manager)
        elif choice == 10:
            object = ec2.QueryFilter(data)
        elif choice == 11:
            object = ecr.SetLifecycle(data = data, manager = resource_manager)
        elif choice == 12:
            object = route53.SetQueryLogging(data = data, manager = resource_manager)
        elif choice == 13:
            object = servicecatalog.RemoveSharedAccounts(data = data, manager = resource_manager)
        elif choice == 14:
            object = account.SetAccountPasswordPolicy(data = data, manager = resource_manager)
        elif choice == 15:
            object = account.ServiceLimit(data = data, manager = resource_manager)
        elif choice == 16:
            object = account.EnableDataEvents(data = data, manager = resource_manager)
        elif choice == 17:
            object = account.SetS3PublicBlock(data = data, manager = resource_manager)
        elif choice == 18:
            object = account.GlueCatalogEncryptionEnabled(data)
        elif choice == 19:
             object = ebs.CopySnapshot(data = data, manager = resource_manager)
        elif choice == 20:
             object = ebs.EncryptInstanceVolumes(data = data, manager = resource_manager)
        elif choice == 21:
             object = ebs.CreateSnapshot(data = data, manager = resource_manager)
        elif choice == 22:
             object = ebs.ModifyVolume(data = data, manager = resource_manager)
        elif choice == 23:
             object = eks.UpdateConfig(data = data, manager = resource_manager)
        elif choice == 24:
             object = redshift.SetRedshiftLogging(data = data, manager = resource_manager)
        elif choice == 25:
             object = redshift.RedshiftSetAttributes(data = data, manager = resource_manager)
        elif choice == 26:
             object = glue.SecurityConfigFilter(data)
        elif choice == 27:
             object = asg.PropagateTags(data = data, manager = resource_manager)
        elif choice == 28:
             object = asg.Update(data = data, manager = resource_manager)
        elif choice == 29:
             object = securityhub.SecurityHubFindingFilter(data)
        elif choice == 30:
             object = securityhub.PostFinding(data = data, manager = resource_manager)
        elif choice == 31:
             object = cloudtrail.UpdateTrail(data = data, manager = resource_manager)
        elif choice == 32:
             object = ssm.SendCommand(data = data, manager = resource_manager)
        elif choice == 33:
             object = rds.Delete(data = data, manager = resource_manager)
        elif choice == 34:
             object = rds.SetPermissions(data = data, manager = resource_manager)
        elif choice == 35:
             object = rds.RegionCopySnapshot(data = data, manager = resource_manager)
        elif choice == 36:
             object = rds.ModifyDb(data = data, manager = resource_manager)
        elif choice == 37:
             object = efs.ConfigureLifecycle(data = data, manager = resource_manager)
        elif choice == 38:
             object = rdscluster.ModifyDbCluster(data = data, manager = resource_manager)
        elif choice == 39:
             object = vpc.FlowLogv2Filter(data)
        elif choice == 40:
             object = vpc.DhcpOptionsFilter(data)
        elif choice == 41:
             object = vpc.SGPermission(data)
        elif choice == 42:
             object = vpc.SetPermissions(data = data, manager = resource_manager)
        elif choice == 43:
             object = iam.SetBoundary(data = data, manager = resource_manager)
        elif choice == 44:
             object = iam.SetGroups(data = data, manager = resource_manager)
        elif choice == 45:
             object = iam.SetPolicy(data = data, manager = resource_manager)
        elif choice == 46:
             object = ami.SetDeprecation(data = data, manager = resource_manager)
        elif choice == 47:
             object = ami.SetPermissions(data = data, manager = resource_manager)
        elif choice == 48:
             object = appelb.SetS3Logging(data = data, manager = resource_manager)
        elif choice == 49:
             object = appelb.SetS3Logging(data = data, manager = resource_manager)
        elif choice == 50:
             object = s3.ToggleLogging(data = data, manager = resource_manager)
        elif choice == 51:
             object = s3.BucketEncryption(data = data, manager = resource_manager)
        elif choice == 52:
             object = s3.BucketEncryption(data = data, manager = resource_manager)
        elif choice == 53:
             object = cloudfront.DistributionUpdateAction(data = data, manager = resource_manager)
        elif choice == 54:
             object = cloudfront.BaseUpdateAction(data = data, manager = resource_manager)
        elif choice == 55:
             object = cloudfront.StreamingDistributionUpdateAction(data = data, manager = resource_manager)
        elif choice == 56:
             object = cloudfront.StreamingDistributionUpdateAction(data = data, manager = resource_manager)

        if object:
            object.validate()
    except (exceptions.PolicyValidationError, ValueError):
        pass
#    except (KeyError, TypeError):
#        pass

def _generate_random_dict(fdp):
    map = dict()

    for count in range(fdp.ConsumeIntInRange(1, 100)):
        map[fdp.ConsumeUnicodeNoSurrogates(1024)] = fdp.ConsumeUnicodeNoSurrogates(1024)

    return map


def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()

class FuzzContext:
    def __init__(self, policy):
        self.session_factory = None
        self.options = None
        self.policy = policy
        self.tracer = FuzzTracer()


class FuzzPolicy:
    def __init__(self):
        self.provider_name = "FuzzProviderName"
        self.name = "FuzzName"


class FuzzTracer:
    def subsegment(type):
        return True


if __name__ == "__main__":
    main()

