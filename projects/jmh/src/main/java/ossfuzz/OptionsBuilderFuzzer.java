/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package ossfuzz;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow;

import java.util.Collection;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.results.format.ResultFormatType;
import org.openjdk.jmh.runner.BenchmarkListEntry;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;
import org.openjdk.jmh.runner.options.TimeValue;
import org.openjdk.jmh.runner.options.VerboseMode;
import org.openjdk.jmh.runner.options.WarmupMode;

import org.openjdk.jmh.util.Optional;

public class OptionsBuilderFuzzer {
	
	FuzzedDataProvider m_fuzzedDataProvider;

	Optional<Integer> optionalInt() {
		if (m_fuzzedDataProvider.consumeBoolean()) {
			return Optional.<Integer>of(m_fuzzedDataProvider.consumeInt(1, 1000));
		} else {
			return Optional.<Integer>none();
		}
	}

	int[] intArray() {
		int retval[] = new int[m_fuzzedDataProvider.consumeInt(1,1000)];
		for (int i=0; i<retval.length; ++i) {
			retval[i] = m_fuzzedDataProvider.consumeInt();
		}
		return retval;
	}

	Collection<String> stringCollection() {
		ArrayList<String> s = new ArrayList<String>();
		int n = m_fuzzedDataProvider.consumeInt(1,10);
		for (int i = 0; i < n; ++i) {
			s.add(m_fuzzedDataProvider.consumeString(16));
		}
		return s;
	}

	Optional<Collection<String>> optionalStringCollection() {
		if (m_fuzzedDataProvider.consumeBoolean()) {
			return Optional.<Collection<String>>of(stringCollection());
		} else {
			return Optional.<Collection<String>>none();
		}
	}

	TimeValue timeValue() {
		return TimeValue.seconds(m_fuzzedDataProvider.consumeInt());
	}

	Optional<TimeValue> optionalTimeValue() {
		if (m_fuzzedDataProvider.consumeBoolean()) {
			return Optional.<TimeValue>of(timeValue());
		} else {
			return Optional.<TimeValue>none();
		}
	}

	VerboseMode verboseModeValue() {
		VerboseMode modes[] = VerboseMode.values();
		return modes[m_fuzzedDataProvider.consumeInt(0, modes.length - 1)];
	}

	ResultFormatType resultFormatValue() {
		switch(m_fuzzedDataProvider.consumeInt(0,4)) {
			case 0: return ResultFormatType.TEXT;
			case 1: return ResultFormatType.CSV;
			case 2: return ResultFormatType.SCSV;
			case 3: return ResultFormatType.JSON;
			default: return ResultFormatType.LATEX;
		}
	}

	WarmupMode warmupModeValue() {
		WarmupMode warmupModes[] = WarmupMode.values();
		return warmupModes[m_fuzzedDataProvider.consumeInt(0, warmupModes.length - 1)];
	}

	Mode modeValue() {
		Mode modes[] = Mode.values();
		return modes[m_fuzzedDataProvider.consumeInt(0, modes.length - 1)];
	}

	TimeUnit timeUnitValue() {
		TimeUnit tu[] = TimeUnit.values();
		return tu[m_fuzzedDataProvider.consumeInt(0, tu.length - 1)];
	}
	
	OptionsBuilderFuzzer(FuzzedDataProvider fuzzedDataProvider) {
		m_fuzzedDataProvider = fuzzedDataProvider;
	}

	String stringValue() {
		return m_fuzzedDataProvider.consumeString(16);
	}

	boolean boolValue() {
		return m_fuzzedDataProvider.consumeBoolean();
	}

	int intValue() {
		return m_fuzzedDataProvider.consumeInt();
	}

	void test() {
		try {
			Options options = new OptionsBuilder()
				.exclude(stringValue())
				.output(stringValue())
				.resultFormat(resultFormatValue())
				.result(stringValue())
				.shouldDoGC(boolValue())
				.verbosity(verboseModeValue())
				.shouldFailOnError(boolValue())
				.threads(intValue())
				.threadGroups(intArray())
				.syncIterations(boolValue())
				.warmupIterations(intValue())
				.warmupBatchSize(intValue())
				.warmupTime(timeValue())
				.warmupMode(warmupModeValue())
				.includeWarmup(stringValue())
				.measurementIterations(intValue())
				.measurementTime(timeValue())
				.measurementBatchSize(intValue())
				.mode(modeValue())
				.timeUnit(timeUnitValue())
				.operationsPerInvocation(intValue())
				.forks(intValue())
				.warmupForks(intValue())
				.jvm(stringValue())
				.jvmArgs(stringValue())
				.jvmArgsAppend(stringValue())
				.jvmArgsPrepend(stringValue())
				.timeout(timeValue())
				.build();
		} catch (IllegalArgumentException e) {
			/* ignore */
		}
	}

	public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) {
		OptionsBuilderFuzzer closure = new OptionsBuilderFuzzer(fuzzedDataProvider);
		closure.test();
	}
}