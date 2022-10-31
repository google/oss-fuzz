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

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import org.springframework.boot.configurationprocessor.metadata.ConfigurationMetadata;
import org.springframework.boot.configurationprocessor.metadata.ItemHint;
import org.springframework.boot.configurationprocessor.metadata.ItemMetadata;
import org.springframework.boot.configurationprocessor.metadata.JsonMarshaller;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import java.util.Collections;

public class JsonMarshallerFuzzer {
	public static void fuzzerTestOneInput(FuzzedDataProvider data) {
		ConfigurationMetadata metadata = new ConfigurationMetadata();
		for (int i = 0; i < data.consumeInt(1, 50); i++) {
			switch (data.consumeInt(0, 3)) {
				case 0:
					metadata.add(ItemMetadata.newProperty(
							data.consumeString(50),
							data.consumeString(50),
							data.consumeString(50),
							data.consumeString(10),
							data.consumeString(10),
							data.consumeString(10),
							new String[] { data.consumeString(50), data.consumeString(50) },
							null
					));
					break;
				case 1:
					metadata.add(ItemMetadata.newGroup(
							data.consumeString(50),
							data.consumeString(50),
							null,
							null
					));
					break;
				case 2:
					metadata.add(ItemHint.newHint(data.consumeString(50)));
					break;
				case 3:
					metadata.add(new ItemHint(
							data.consumeString(50),
							null,
							Arrays.asList(new ItemHint.ValueProvider(
									data.consumeString(50),
									Collections.singletonMap(data.consumeString(50),
									data.consumeString(50))
							), new ItemHint.ValueProvider(data.consumeString(50), null))
					));
					break;
			}
		}

		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		JsonMarshaller marshaller = new JsonMarshaller();
		try {
			marshaller.write(metadata, outputStream);
			outputStream.toString();
			marshaller.read(new ByteArrayInputStream(outputStream.toByteArray()));
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
}