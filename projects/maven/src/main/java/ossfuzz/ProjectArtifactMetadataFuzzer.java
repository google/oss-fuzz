// Copyright 2022 Google LLC
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
////////////////////////////////////////////////////////////////////////////////

package ossfuzz;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;

import org.apache.maven.project.artifact.ProjectArtifactMetadata;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.DefaultArtifact;
import org.apache.maven.artifact.InvalidArtifactRTException;
import org.apache.maven.artifact.handler.DefaultArtifactHandler;

import java.util.ArrayList;

public class ProjectArtifactMetadataFuzzer {

	public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) {

		Artifact a;
		try {
			a = new DefaultArtifact(
					fuzzedDataProvider.consumeString(10),
					fuzzedDataProvider.consumeString(10),
					fuzzedDataProvider.consumeString(10),
					fuzzedDataProvider.consumeString(10),
					fuzzedDataProvider.consumeString(10),
					fuzzedDataProvider.consumeString(10),
					new DefaultArtifactHandler(fuzzedDataProvider.consumeString(10)));
		} catch (IllegalArgumentException e) {
			return;
		} catch (InvalidArtifactRTException e) {
			return;
		}

		ProjectArtifactMetadata projectArtifactMetadata = new ProjectArtifactMetadata(a);

		a.getVersion();
		try {
			a.setVersion(fuzzedDataProvider.consumeString(10));
		} catch (IllegalArgumentException e) {
		}
		a.getScope();
		a.getType();
		a.getClassifier();
		a.hasClassifier();
		try {
			a.setBaseVersion(fuzzedDataProvider.consumeString(10));
		} catch (IllegalArgumentException e) {
		}

		a.getDependencyConflictId();
		a.getMetadataList();
		a.getRepository();
		a.getDownloadUrl();
		try {
			a.setDownloadUrl(fuzzedDataProvider.consumeString(10));
		} catch (IllegalArgumentException e) {
		}
		a.getDependencyFilter();
		a.getArtifactHandler();
		try {
			a.setDependencyTrail(new ArrayList<String>() {

				{
					add(fuzzedDataProvider.consumeString(10));
				}
			});
		} catch (IllegalArgumentException e) {
		}

		try {
			a.setScope(fuzzedDataProvider.consumeString(10));
		} catch (IllegalArgumentException e) {
		}
		a.getVersionRange();
		try {
			a.selectVersion(fuzzedDataProvider.consumeString(10));
		} catch (IllegalArgumentException e) {
		}

		try {
			a.setGroupId(fuzzedDataProvider.consumeString(10));
		} catch (IllegalArgumentException e) {
		}
		try {
			a.setArtifactId(fuzzedDataProvider.consumeString(10));
		} catch (IllegalArgumentException e) {
		}
		a.isSnapshot();
		try {
			a.setResolved(fuzzedDataProvider.consumeBoolean());
		} catch (IllegalArgumentException e) {
		}
		try {
			a.setResolvedVersion(fuzzedDataProvider.consumeRemainingAsString());
		} catch (IllegalArgumentException e) {
		}
		a.setRelease(fuzzedDataProvider.consumeBoolean());
		a.getAvailableVersions();
		a.isOptional();
		a.setOptional(fuzzedDataProvider.consumeBoolean());

		projectArtifactMetadata.getGroupId();
		projectArtifactMetadata.getArtifactId();
		projectArtifactMetadata.getBaseVersion();
		projectArtifactMetadata.getRemoteFilename();
		projectArtifactMetadata.storedInArtifactVersionDirectory();
		projectArtifactMetadata.getKey();
	}
}