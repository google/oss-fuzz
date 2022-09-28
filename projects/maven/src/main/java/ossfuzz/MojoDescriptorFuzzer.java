// Copyright 2021 Google LLC
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

import org.apache.maven.plugin.descriptor.MojoDescriptor;
import org.apache.maven.plugin.descriptor.Parameter;
import org.apache.maven.plugin.descriptor.PluginDescriptor;

import java.util.ArrayList;
import java.util.List;

import org.apache.maven.plugin.descriptor.DuplicateParameterException;

public class MojoDescriptorFuzzer {

	public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) {

		MojoDescriptor mojoDescriptor = new MojoDescriptor();
		List<Parameter> listParameters = new ArrayList<Parameter>();
		int n = fuzzedDataProvider.consumeInt(1, 100);
		for (int i = 0; i <= n; i++) {
			Parameter param1 = new Parameter();
			param1.setName(fuzzedDataProvider.consumeString(10));
			param1.setDefaultValue(fuzzedDataProvider.consumeString(10));
			listParameters.add(param1);
		}
		try {
			mojoDescriptor.setParameters(listParameters);
		} catch (DuplicateParameterException e) {
		}

		mojoDescriptor.setPluginDescriptor(new PluginDescriptor());
		mojoDescriptor.getComponentType();
		mojoDescriptor.getLanguage();
		mojoDescriptor.setLanguage(fuzzedDataProvider.consumeString(10));
		mojoDescriptor.getDeprecated();
		mojoDescriptor.setDeprecated(fuzzedDataProvider.consumeString(10));
		mojoDescriptor.setDependencyCollectionRequired(fuzzedDataProvider.consumeString(10));
		mojoDescriptor.getDependencyCollectionRequired();
		mojoDescriptor.setProjectRequired(fuzzedDataProvider.consumeBoolean());
		mojoDescriptor.isProjectRequired();
		mojoDescriptor.setOnlineRequired(fuzzedDataProvider.consumeBoolean());
		mojoDescriptor.isOnlineRequired();
		mojoDescriptor.requiresOnline();
		mojoDescriptor.setPhase(fuzzedDataProvider.consumeString(10));
		mojoDescriptor.getPhase();
		mojoDescriptor.setSince(fuzzedDataProvider.consumeString(10));
		mojoDescriptor.getSince();
		mojoDescriptor.setGoal(fuzzedDataProvider.consumeString(10));
		mojoDescriptor.getGoal();
		mojoDescriptor.setExecutePhase(fuzzedDataProvider.consumeString(10));
		mojoDescriptor.getExecutePhase();
		mojoDescriptor.alwaysExecute();
		mojoDescriptor.setExecutionStrategy(fuzzedDataProvider.consumeString(10));
		mojoDescriptor.getExecutionStrategy();
		mojoDescriptor.getRole();
		mojoDescriptor.getRoleHint();
		mojoDescriptor.getId();
		mojoDescriptor.getFullGoalName();
		mojoDescriptor.getComponentType();
		mojoDescriptor.getPluginDescriptor();
		mojoDescriptor.setInheritedByDefault(fuzzedDataProvider.consumeBoolean());
		mojoDescriptor.isInheritedByDefault();
		mojoDescriptor.hashCode();
		mojoDescriptor.setExecuteLifecycle(fuzzedDataProvider.consumeString(10));
		mojoDescriptor.getExecuteLifecycle();
		mojoDescriptor.setAggregator(fuzzedDataProvider.consumeBoolean());
		mojoDescriptor.isAggregator();
		mojoDescriptor.setDirectInvocationOnly(fuzzedDataProvider.consumeBoolean());
		mojoDescriptor.isDirectInvocationOnly();
		mojoDescriptor.setRequiresReports(fuzzedDataProvider.consumeBoolean());
		mojoDescriptor.isRequiresReports();
		mojoDescriptor.setExecuteGoal(fuzzedDataProvider.consumeRemainingAsString());
		mojoDescriptor.getExecuteGoal();
		mojoDescriptor.setThreadSafe(fuzzedDataProvider.consumeBoolean());
		mojoDescriptor.isThreadSafe();
		mojoDescriptor.isForking();
		mojoDescriptor.getParameters();
	}
}