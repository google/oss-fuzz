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

import org.apache.commons.io.output.NullOutputStream;
import org.apache.poi.ooxml.POIXMLException;
import org.apache.poi.openxml4j.exceptions.OpenXML4JException;
import org.apache.poi.openxml4j.exceptions.OpenXML4JRuntimeException;
import org.apache.poi.util.RecordFormatException;
import org.apache.poi.xwpf.extractor.XWPFWordExtractor;
import org.apache.poi.xwpf.usermodel.XWPFDocument;

public class POIXWPFFuzzer {
	public static void fuzzerInitialize() {
		POIFuzzer.adjustLimits();
	}

	@SuppressWarnings("ResultOfMethodCallIgnored")
	public static void fuzzerTestOneInput(byte[] input) {
		try (XWPFDocument doc = new XWPFDocument(new ByteArrayInputStream(input))) {
			doc.write(NullOutputStream.INSTANCE);

			// if the document can be parsed, trigger some of the getters
			try {
				doc.getAllEmbeddedParts();
				doc.getAllPictures();
				doc.getAllPackagePictures();
				doc.getPackage();
				doc.getPackagePart();
				doc.getProperties();
				doc.getRelations();
				doc.getCharts();
				doc.getBodyElements();
				doc.getBodyElementsIterator();
				doc.getBodyElementsSpliterator();
			} catch (OpenXML4JException | POIXMLException e) {
				// expected
			}

			try (XWPFWordExtractor extractor = new XWPFWordExtractor(doc)) {
				POIFuzzer.checkExtractor(extractor);
			}
		} catch (IOException | POIXMLException | RecordFormatException | OpenXML4JRuntimeException |
				 IllegalArgumentException | IllegalStateException | IndexOutOfBoundsException e) {
			// expected
		}
	}
}
