// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package probes

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ossf/scorecard/v5/checker"
	"github.com/ossf/scorecard/v5/clients"

	gfh "github.com/AdaLogics/go-fuzz-headers"

	"github.com/ossf/scorecard/v5/probes/archived"
	"github.com/ossf/scorecard/v5/probes/blocksDeleteOnBranches"
	"github.com/ossf/scorecard/v5/probes/blocksForcePushOnBranches"
	"github.com/ossf/scorecard/v5/probes/branchProtectionAppliesToAdmins"
	"github.com/ossf/scorecard/v5/probes/branchesAreProtected"
	"github.com/ossf/scorecard/v5/probes/codeApproved"
	"github.com/ossf/scorecard/v5/probes/codeReviewOneReviewers"
	"github.com/ossf/scorecard/v5/probes/contributorsFromOrgOrCompany"
	"github.com/ossf/scorecard/v5/probes/createdRecently"
	"github.com/ossf/scorecard/v5/probes/dependencyUpdateToolConfigured"
	"github.com/ossf/scorecard/v5/probes/dismissesStaleReviews"
	"github.com/ossf/scorecard/v5/probes/fuzzed"
	"github.com/ossf/scorecard/v5/probes/hasBinaryArtifacts"
	"github.com/ossf/scorecard/v5/probes/hasDangerousWorkflowScriptInjection"
	"github.com/ossf/scorecard/v5/probes/hasDangerousWorkflowUntrustedCheckout"
	"github.com/ossf/scorecard/v5/probes/hasFSFOrOSIApprovedLicense"
	"github.com/ossf/scorecard/v5/probes/hasLicenseFile"
	"github.com/ossf/scorecard/v5/probes/hasNoGitHubWorkflowPermissionUnknown"
	"github.com/ossf/scorecard/v5/probes/hasOSVVulnerabilities"
	"github.com/ossf/scorecard/v5/probes/hasOpenSSFBadge"
	"github.com/ossf/scorecard/v5/probes/hasPermissiveLicense"
	"github.com/ossf/scorecard/v5/probes/hasRecentCommits"
	"github.com/ossf/scorecard/v5/probes/hasReleaseSBOM"
	"github.com/ossf/scorecard/v5/probes/hasSBOM"
	"github.com/ossf/scorecard/v5/probes/hasUnverifiedBinaryArtifacts"
	"github.com/ossf/scorecard/v5/probes/issueActivityByProjectMember"
	"github.com/ossf/scorecard/v5/probes/jobLevelPermissions"
	"github.com/ossf/scorecard/v5/probes/packagedWithAutomatedWorkflow"
	"github.com/ossf/scorecard/v5/probes/pinsDependencies"
	"github.com/ossf/scorecard/v5/probes/releasesAreSigned"
	"github.com/ossf/scorecard/v5/probes/releasesHaveProvenance"
	"github.com/ossf/scorecard/v5/probes/releasesHaveVerifiedProvenance"
	"github.com/ossf/scorecard/v5/probes/requiresApproversForPullRequests"
	"github.com/ossf/scorecard/v5/probes/requiresCodeOwnersReview"
	"github.com/ossf/scorecard/v5/probes/requiresLastPushApproval"
	"github.com/ossf/scorecard/v5/probes/requiresPRsToChangeCode"
	"github.com/ossf/scorecard/v5/probes/requiresUpToDateBranches"
	"github.com/ossf/scorecard/v5/probes/runsStatusChecksBeforeMerging"
	"github.com/ossf/scorecard/v5/probes/sastToolConfigured"
	"github.com/ossf/scorecard/v5/probes/sastToolRunsOnAllCommits"
	"github.com/ossf/scorecard/v5/probes/securityPolicyContainsLinks"
	"github.com/ossf/scorecard/v5/probes/securityPolicyContainsText"
	"github.com/ossf/scorecard/v5/probes/securityPolicyContainsVulnerabilityDisclosure"
	"github.com/ossf/scorecard/v5/probes/securityPolicyPresent"
	"github.com/ossf/scorecard/v5/probes/testsRunInCI"
	"github.com/ossf/scorecard/v5/probes/topLevelPermissions"
	"github.com/ossf/scorecard/v5/probes/unsafeblock"
	"github.com/ossf/scorecard/v5/probes/webhooksUseSecrets"
)

var (
	probeDefinitionPath = "/tmp/probedefinitions"
	emptyName           = ""
)

func writeProbeFile(probeId, yamlContents string) error {
	err := os.MkdirAll(filepath.Join(probeDefinitionPath, probeId), 0750)
	if err != nil {
		return err
	}
	err = os.WriteFile(filepath.Join(probeDefinitionPath, probeId, "def.yml"),
		[]byte(yamlContents),
		0660)
	return err
}

// Scorecard reads from the filesystem, so we write the def.yml files to disk
func init() {
	err := os.MkdirAll(probeDefinitionPath, 0750)
	if err != nil {
		panic(err)
	}
	yamlContents := archived.YmlFile
	if err = writeProbeFile("archived", yamlContents); err != nil {
		panic(err)
	}
	yamlContents = blocksDeleteOnBranches.YmlFile
	if err = writeProbeFile("blocksDeleteOnBranches", yamlContents); err != nil {
		panic(err)
	}
	yamlContents = blocksForcePushOnBranches.YmlFile
	if err = writeProbeFile("blocksForcePushOnBranches", yamlContents); err != nil {
		panic(err)
	}
	yamlContents = branchProtectionAppliesToAdmins.YmlFile
	if err = writeProbeFile("branchProtectionAppliesToAdmins", yamlContents); err != nil {
		panic(err)
	}
	yamlContents = branchesAreProtected.YmlFile
	if err = writeProbeFile("branchesAreProtected", yamlContents); err != nil {
		panic(err)
	}
	yamlContents = codeApproved.YmlFile
	if err = writeProbeFile("codeApproved", yamlContents); err != nil {
		panic(err)
	}
	yamlContents = codeReviewOneReviewers.YmlFile
	if err = writeProbeFile("codeReviewOneReviewers", yamlContents); err != nil {
		panic(err)
	}
	yamlContents = contributorsFromOrgOrCompany.YmlFile
	if err = writeProbeFile("contributorsFromOrgOrCompany", yamlContents); err != nil {
		panic(err)
	}
	yamlContents = createdRecently.YmlFile
	if err = writeProbeFile("createdRecently", yamlContents); err != nil {
		panic(err)
	}
	yamlContents = dependencyUpdateToolConfigured.YmlFile
	if err = writeProbeFile("dependencyUpdateToolConfigured", yamlContents); err != nil {
		panic(err)
	}
	yamlContents = dismissesStaleReviews.YmlFile
	if err = writeProbeFile("dismissesStaleReviews", yamlContents); err != nil {
		panic(err)
	}
	yamlContents = fuzzed.YmlFile
	if err = writeProbeFile("fuzzed", yamlContents); err != nil {
		panic(err)
	}
	yamlContents = hasBinaryArtifacts.YmlFile
	if err = writeProbeFile("hasBinaryArtifacts", yamlContents); err != nil {
		panic(err)
	}
	yamlContents = hasDangerousWorkflowScriptInjection.YmlFile
	if err = writeProbeFile("hasDangerousWorkflowScriptInjection", yamlContents); err != nil {
		panic(err)
	}
	yamlContents = hasDangerousWorkflowUntrustedCheckout.YmlFile
	if err = writeProbeFile("hasDangerousWorkflowUntrustedCheckout", yamlContents); err != nil {
		panic(err)
	}
	yamlContents = hasFSFOrOSIApprovedLicense.YmlFile
	if err = writeProbeFile("hasFSFOrOSIApprovedLicense", yamlContents); err != nil {
		panic(err)
	}
	yamlContents = hasLicenseFile.YmlFile
	if err = writeProbeFile("hasLicenseFile", yamlContents); err != nil {
		panic(err)
	}
	yamlContents = hasNoGitHubWorkflowPermissionUnknown.YmlFile
	if err = writeProbeFile("hasNoGitHubWorkflowPermissionUnknown", yamlContents); err != nil {
		panic(err)
	}
	yamlContents = hasOSVVulnerabilities.YmlFile
	if err = writeProbeFile("hasOSVVulnerabilities", yamlContents); err != nil {
		panic(err)
	}
	yamlContents = hasOpenSSFBadge.YmlFile
	if err = writeProbeFile("hasOpenSSFBadge", yamlContents); err != nil {
		panic(err)
	}
	yamlContents = hasPermissiveLicense.YmlFile
	if err = writeProbeFile("hasPermissiveLicense", yamlContents); err != nil {
		panic(err)
	}
	yamlContents = hasRecentCommits.YmlFile
	if err = writeProbeFile("hasRecentCommits", yamlContents); err != nil {
		panic(err)
	}
	yamlContents = hasReleaseSBOM.YmlFile
	if err = writeProbeFile("hasReleaseSBOM", yamlContents); err != nil {
		panic(err)
	}
	yamlContents = hasSBOM.YmlFile
	if err = writeProbeFile("hasSBOM", yamlContents); err != nil {
		panic(err)
	}
	yamlContents = hasUnverifiedBinaryArtifacts.YmlFile
	if err = writeProbeFile("hasUnverifiedBinaryArtifacts", yamlContents); err != nil {
		panic(err)
	}
	yamlContents = issueActivityByProjectMember.YmlFile
	if err = writeProbeFile("issueActivityByProjectMember", yamlContents); err != nil {
		panic(err)
	}
	yamlContents = jobLevelPermissions.YmlFile
	if err = writeProbeFile("jobLevelPermissions", yamlContents); err != nil {
		panic(err)
	}
	yamlContents = packagedWithAutomatedWorkflow.YmlFile
	if err = writeProbeFile("packagedWithAutomatedWorkflow", yamlContents); err != nil {
		panic(err)
	}
	yamlContents = pinsDependencies.YmlFile
	if err = writeProbeFile("pinsDependencies", yamlContents); err != nil {
		panic(err)
	}
	yamlContents = releasesAreSigned.YmlFile
	if err = writeProbeFile("releasesAreSigned", yamlContents); err != nil {
		panic(err)
	}
	yamlContents = releasesHaveProvenance.YmlFile
	if err = writeProbeFile("releasesHaveProvenance", yamlContents); err != nil {
		panic(err)
	}
	yamlContents = releasesHaveVerifiedProvenance.YmlFile
	if err = writeProbeFile("releasesHaveVerifiedProvenance", yamlContents); err != nil {
		panic(err)
	}
	yamlContents = requiresApproversForPullRequests.YmlFile
	if err = writeProbeFile("requiresApproversForPullRequests", yamlContents); err != nil {
		panic(err)
	}
	yamlContents = requiresCodeOwnersReview.YmlFile
	if err = writeProbeFile("requiresCodeOwnersReview", yamlContents); err != nil {
		panic(err)
	}
	yamlContents = requiresLastPushApproval.YmlFile
	if err = writeProbeFile("requiresLastPushApproval", yamlContents); err != nil {
		panic(err)
	}
	yamlContents = requiresPRsToChangeCode.YmlFile
	if err = writeProbeFile("requiresPRsToChangeCode", yamlContents); err != nil {
		panic(err)
	}
	yamlContents = requiresUpToDateBranches.YmlFile
	if err = writeProbeFile("requiresUpToDateBranches", yamlContents); err != nil {
		panic(err)
	}
	yamlContents = runsStatusChecksBeforeMerging.YmlFile
	if err = writeProbeFile("runsStatusChecksBeforeMerging", yamlContents); err != nil {
		panic(err)
	}
	yamlContents = sastToolConfigured.YmlFile
	if err = writeProbeFile("sastToolConfigured", yamlContents); err != nil {
		panic(err)
	}
	yamlContents = sastToolRunsOnAllCommits.YmlFile
	if err = writeProbeFile("sastToolRunsOnAllCommits", yamlContents); err != nil {
		panic(err)
	}
	yamlContents = securityPolicyContainsLinks.YmlFile
	if err = writeProbeFile("securityPolicyContainsLinks", yamlContents); err != nil {
		panic(err)
	}
	yamlContents = securityPolicyContainsText.YmlFile
	if err = writeProbeFile("securityPolicyContainsText", yamlContents); err != nil {
		panic(err)
	}
	yamlContents = securityPolicyContainsVulnerabilityDisclosure.YmlFile
	if err = writeProbeFile("securityPolicyContainsVulnerabilityDisclosure", yamlContents); err != nil {
		panic(err)
	}
	yamlContents = securityPolicyPresent.YmlFile
	if err = writeProbeFile("securityPolicyPresent", yamlContents); err != nil {
		panic(err)
	}
	yamlContents = testsRunInCI.YmlFile
	if err = writeProbeFile("testsRunInCI", yamlContents); err != nil {
		panic(err)
	}
	yamlContents = topLevelPermissions.YmlFile
	if err = writeProbeFile("topLevelPermissions", yamlContents); err != nil {
		panic(err)
	}
	yamlContents = unsafeblock.YmlFile
	if err = writeProbeFile("unsafeblock", yamlContents); err != nil {
		panic(err)
	}
	yamlContents = webhooksUseSecrets.YmlFile
	if err = writeProbeFile("webhooksUseSecrets", yamlContents); err != nil {
		panic(err)
	}
}

func FuzzProbes(f *testing.F) {
	f.Fuzz(func(t *testing.T, callType int, data []byte) {
		fdp := gfh.NewConsumer(data)

		switch callType % 31 {
		case 0:
			fuzzers := make([]checker.Tool, 0)
			fdp.GenerateStruct(&fuzzers)
			if len(fuzzers) == 0 {
				return
			}
			r := &checker.RawResults{
				FuzzingResults: checker.FuzzingData{
					Fuzzers: fuzzers,
				},
			}
			_, _, err := fuzzed.Run(r)
			if err != nil {
				panic(err)
			}
		case 1:
			r, err := createRawBranchProtectionsData(fdp)
			if err != nil {
				return
			}
			_, _, _ = blocksDeleteOnBranches.Run(r)
		case 2:
			r, err := createRawBranchProtectionsData(fdp)
			if err != nil {
				return
			}
			_, _, _ = branchProtectionAppliesToAdmins.Run(r)
		case 3:
			r, err := createRawBranchProtectionsData(fdp)
			if err != nil {
				return
			}
			_, _, _ = branchesAreProtected.Run(r)
		case 4:
			defaultBranchChangesets := make([]checker.Changeset, 0)
			fdp.GenerateStruct(&defaultBranchChangesets)
			if len(defaultBranchChangesets) == 0 {
				return
			}
			r := &checker.RawResults{
				CodeReviewResults: checker.CodeReviewData{
					DefaultBranchChangesets: defaultBranchChangesets,
				},
			}
			_, _, _ = codeApproved.Run(r)
		case 5:
			defaultBranchChangesets := make([]checker.Changeset, 0)
			fdp.GenerateStruct(&defaultBranchChangesets)
			if len(defaultBranchChangesets) == 0 {
				return
			}
			r := &checker.RawResults{
				CodeReviewResults: checker.CodeReviewData{
					DefaultBranchChangesets: defaultBranchChangesets,
				},
			}
			_, _, _ = codeReviewOneReviewers.Run(r)
		case 6:
			users := make([]clients.User, 0)
			fdp.GenerateStruct(&users)
			if len(users) == 0 {
				return
			}
			r := &checker.RawResults{
				ContributorsResults: checker.ContributorsData{
					Users: users,
				},
			}
			_, _, _ = contributorsFromOrgOrCompany.Run(r)
		case 7:
			tools := make([]checker.Tool, 0)
			fdp.GenerateStruct(&tools)
			r := &checker.RawResults{
				DependencyUpdateToolResults: checker.DependencyUpdateToolData{
					Tools: tools,
				},
			}
			_, _, _ = dependencyUpdateToolConfigured.Run(r)
		case 8:
			r, err := createRawBranchProtectionsData(fdp)
			if err != nil {
				return
			}
			_, _, _ = dismissesStaleReviews.Run(r)
		case 9:
			files := make([]checker.File, 0)
			fdp.GenerateStruct(&files)
			if len(files) == 0 {
				return
			}
			r := &checker.RawResults{
				BinaryArtifactResults: checker.BinaryArtifactData{
					Files: files,
				},
			}
			_, _, _ = hasBinaryArtifacts.Run(r)
		case 10:
			files := make([]checker.File, 0)
			fdp.GenerateStruct(&files)
			if len(files) == 0 {
				return
			}
			r := &checker.RawResults{
				BinaryArtifactResults: checker.BinaryArtifactData{
					Files: files,
				},
			}
			_, _, _ = hasUnverifiedBinaryArtifacts.Run(r)
		case 11:
			workflows := make([]checker.DangerousWorkflow, 0)
			fdp.GenerateStruct(&workflows)
			if len(workflows) == 0 {
				return
			}
			// Create temp file
			fileContents, err := fdp.GetBytes()
			if err != nil {
				return
			}
			tmpDir := t.TempDir()
			err = os.WriteFile(filepath.Join(tmpDir, "workflowPath.yml"), fileContents, 0755)
			if err != nil {
				// Panic as this should not happen and it may block the fuzzer
				// if it fails here.
				panic(err)
			}
			r := &checker.RawResults{
				DangerousWorkflowResults: checker.DangerousWorkflowData{
					NumWorkflows: len(workflows),
					Workflows:    workflows,
				},
				Metadata: checker.MetadataData{
					Metadata: map[string]string{
						"localPath": filepath.Join(tmpDir, "workflowPath.yml"),
					},
				},
			}
			_, _, _ = hasDangerousWorkflowScriptInjection.Run(r)
		case 12:
			workflows := make([]checker.DangerousWorkflow, 0)
			fdp.GenerateStruct(&workflows)
			if len(workflows) == 0 {
				return
			}
			// Create temp file
			fileContents, err := fdp.GetBytes()
			if err != nil {
				return
			}
			tmpDir := t.TempDir()
			err = os.WriteFile(filepath.Join(tmpDir, "workflowPath.yml"), fileContents, 0755)
			if err != nil {
				// Panic as this should not happen and it may block the fuzzer
				// if it fails here.
				panic(err)
			}
			r := &checker.RawResults{
				DangerousWorkflowResults: checker.DangerousWorkflowData{
					NumWorkflows: len(workflows),
					Workflows:    workflows,
				},
				Metadata: checker.MetadataData{
					Metadata: map[string]string{
						"localPath": filepath.Join(tmpDir, "workflowPath.yml"),
					},
				},
			}
			_, _, _ = hasDangerousWorkflowUntrustedCheckout.Run(r)
		case 13:
			licenseFiles := make([]checker.LicenseFile, 0)
			fdp.GenerateStruct(&licenseFiles)
			if len(licenseFiles) == 0 {
				return
			}
			r := &checker.RawResults{
				LicenseResults: checker.LicenseData{
					LicenseFiles: licenseFiles,
				},
			}
			_, _, _ = hasPermissiveLicense.Run(r)
		case 14:
			sbomFiles := make([]checker.SBOM, 0)
			fdp.GenerateStruct(&sbomFiles)
			if len(sbomFiles) == 0 {
				return
			}
			r := &checker.RawResults{
				SBOMResults: checker.SBOMData{
					SBOMFiles: sbomFiles,
				},
			}
			hasReleaseSBOM.Run(r)
		case 15:
			sbomFiles := make([]checker.SBOM, 0)
			fdp.GenerateStruct(&sbomFiles)
			if len(sbomFiles) == 0 {
				return
			}
			r := &checker.RawResults{
				SBOMResults: checker.SBOMData{
					SBOMFiles: sbomFiles,
				},
			}
			hasSBOM.Run(r)
		case 16:
			issues := make([]clients.Issue, 0)
			fdp.GenerateStruct(&issues)
			if len(issues) == 0 {
				return
			}
			commits := make([]clients.Commit, 0)
			fdp.GenerateStruct(&commits)
			if len(commits) == 0 {
				return
			}
			r := &checker.RawResults{
				MaintainedResults: checker.MaintainedData{
					CreatedAt:            time.Now(),
					Issues:               issues,
					DefaultBranchCommits: commits,
					ArchivedStatus: checker.ArchivedStatus{
						Status: false,
					},
				},
			}
			issueActivityByProjectMember.Run(r)
		case 17:
			permissions := make([]checker.TokenPermission, 0)
			fdp.GenerateStruct(&permissions)
			if len(permissions) == 0 {
				return
			}

			r := &checker.RawResults{
				TokenPermissionsResults: checker.TokenPermissionsData{
					TokenPermissions: permissions,
					NumTokens:        len(permissions),
				},
			}
			jobLevelPermissions.Run(r)
		case 18:
			packages := make([]checker.Package, 0)
			fdp.GenerateStruct(&packages)
			if len(packages) == 0 {
				return
			}

			r := &checker.RawResults{
				PackagingResults: checker.PackagingData{
					Packages: packages,
				},
			}
			packagedWithAutomatedWorkflow.Run(r)
		case 19:
			dependencies := make([]checker.Dependency, 0)
			fdp.GenerateStruct(&dependencies)
			if len(dependencies) == 0 {
				return
			}
			processingErrors := make([]checker.ElementError, 0)
			fdp.GenerateStruct(&processingErrors)
			if len(processingErrors) == 0 {
				return
			}

			r := &checker.RawResults{
				PinningDependenciesResults: checker.PinningDependenciesData{
					Dependencies:     dependencies,
					ProcessingErrors: processingErrors,
				},
			}
			pinsDependencies.Run(r)
		case 20:
			releases := make([]clients.Release, 0)
			fdp.GenerateStruct(&releases)
			if len(releases) == 0 {
				return
			}

			r := &checker.RawResults{
				SignedReleasesResults: checker.SignedReleasesData{
					Releases: releases,
				},
			}
			releasesAreSigned.Run(r)
		case 21:
			releases := make([]clients.Release, 0)
			fdp.GenerateStruct(&releases)
			if len(releases) == 0 {
				return
			}

			r := &checker.RawResults{
				SignedReleasesResults: checker.SignedReleasesData{
					Releases: releases,
				},
			}
			releasesHaveProvenance.Run(r)
		case 22:
			packages := make([]checker.ProjectPackage, 0)
			fdp.GenerateStruct(&packages)
			if len(packages) == 0 {
				return
			}

			r := &checker.RawResults{
				SignedReleasesResults: checker.SignedReleasesData{
					Packages: packages,
				},
			}
			releasesHaveVerifiedProvenance.Run(r)
		case 23:
			r, err := createRawBranchProtectionsData(fdp)
			if err != nil {
				return
			}
			_, _, _ = requiresApproversForPullRequests.Run(r)
		case 24:
			r, err := createRawBranchProtectionsData(fdp)
			if err != nil {
				return
			}
			_, _, _ = requiresCodeOwnersReview.Run(r)
		case 25:
			r, err := createRawBranchProtectionsData(fdp)
			if err != nil {
				return
			}
			_, _, _ = requiresLastPushApproval.Run(r)
		case 26:
			r, err := createRawBranchProtectionsData(fdp)
			if err != nil {
				return
			}
			_, _, _ = requiresPRsToChangeCode.Run(r)
		case 27:
			r, err := createRawBranchProtectionsData(fdp)
			if err != nil {
				return
			}
			_, _, _ = requiresUpToDateBranches.Run(r)
		case 28:
			r, err := createRawBranchProtectionsData(fdp)
			if err != nil {
				return
			}
			_, _, _ = runsStatusChecksBeforeMerging.Run(r)
		case 29:
			workflows := make([]checker.SASTWorkflow, 0)
			fdp.GenerateStruct(&workflows)
			if len(workflows) == 0 {
				return
			}
			commits := make([]checker.SASTCommit, 0)
			fdp.GenerateStruct(&commits)
			if len(commits) == 0 {
				return
			}
			r := &checker.RawResults{
				SASTResults: checker.SASTData{
					Workflows:    workflows,
					Commits:      commits,
					NumWorkflows: len(workflows),
				},
			}
			_, _, _ = sastToolConfigured.Run(r)
			_, _, _ = sastToolRunsOnAllCommits.Run(r)
		case 30:
			ciInfo := make([]checker.RevisionCIInfo, 0)
			fdp.GenerateStruct(&ciInfo)
			if len(ciInfo) == 0 {
				return
			}
			r := &checker.RawResults{
				CITestResults: checker.CITestData{
					CIInfo: ciInfo,
				},
			}
			_, _, _ = testsRunInCI.Run(r)
		}
	})
}

func createRawBranchProtectionsData(fdp *gfh.ConsumeFuzzer) (*checker.RawResults, error) {
	branches := make([]clients.BranchRef, 0)
	fdp.GenerateStruct(&branches)
	if len(branches) == 0 {
		return nil, fmt.Errorf("created no branches")
	}
	for _, branch := range branches {
		if branch.Name == nil {
			return nil, fmt.Errorf("created branch with nil name")
		}
	}
	bpd := checker.BranchProtectionsData{
		Branches: branches,
	}
	r := &checker.RawResults{
		BranchProtectionResults: bpd,
	}
	return r, nil
}
