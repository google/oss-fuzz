// Copyright 2023 Google LLC
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

package org.apache.poi;

import java.io.ByteArrayInputStream;
import java.io.IOException;

import org.apache.poi.hmef.HMEFMessage;
import org.apache.poi.util.RecordFormatException;

public class POIHMEFFuzzer {
	public static void fuzzerInitialize() {
		POIFuzzer.adjustLimits();
	}

	public static void fuzzerTestOneInput(byte[] input) {
		try {
			HMEFMessage msg = new HMEFMessage(new ByteArrayInputStream(input));
			//noinspection ResultOfMethodCallIgnored
			msg.getAttachments();
			msg.getBody();
			//noinspection ResultOfMethodCallIgnored
			msg.getMessageAttributes();
			msg.getSubject();
			//noinspection ResultOfMethodCallIgnored
			msg.getMessageMAPIAttributes();
		} catch (IOException | IllegalArgumentException | IllegalStateException | RecordFormatException |
				ArrayIndexOutOfBoundsException e) {
			// expected here
		}
	}
}
