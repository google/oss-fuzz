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
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;

public class ByteBufUtilFuzzer {

    private FuzzedDataProvider fuzzedDataProvider;

	public ByteBufUtilFuzzer(FuzzedDataProvider fuzzedDataProvider) {
		this.fuzzedDataProvider = fuzzedDataProvider;

	}

	void test() {
		try {
			var fromIndex = fuzzedDataProvider.consumeInt();
			var toIndex = fuzzedDataProvider.consumeInt();
			var value = fuzzedDataProvider.consumeByte();
			byte[] bytes = fuzzedDataProvider.consumeRemainingAsBytes();
			var buf = Unpooled.copiedBuffer(bytes);
			if (bytes.length != 0) {
				// fromIndex and toIndex need to be valid indices, or indexOf
				// will throw an out of bounds exception, which is not
				// documented
				ByteBufUtil.indexOf(buf, Math.abs(fromIndex % bytes.length), Math.abs(toIndex % bytes.length), value);
			}

		} catch (IllegalArgumentException e) {

		}

	}

	public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) {

		ByteBufUtilFuzzer fixture = new ByteBufUtilFuzzer(fuzzedDataProvider);
		fixture.test();
	}
    
}