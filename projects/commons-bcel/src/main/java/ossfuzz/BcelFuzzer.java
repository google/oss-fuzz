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

import java.io.ByteArrayInputStream;
import java.io.IOException;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;

import org.apache.bcel.classfile.*;

public class BcelFuzzer {

	BcelFuzzer(FuzzedDataProvider fuzzedDataProvider) {

	}

	void test(FuzzedDataProvider fuzzedDataProvider) throws Exception {
		var m_string = fuzzedDataProvider.consumeString(10);
		var m_byte = fuzzedDataProvider.consumeRemainingAsBytes();
		try {
			new ClassParser(new ByteArrayInputStream(m_byte), m_string).parse();
		} catch (IOException e) {
			// documented ignore
		} catch (ClassFormatException e) {
			// documented ignore
		}
	}

	public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) throws Exception {
		BcelFuzzer testClosure = new BcelFuzzer(fuzzedDataProvider);

		testClosure.test(fuzzedDataProvider);
	}
}