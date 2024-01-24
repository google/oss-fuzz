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
import org.apache.poi.openxml4j.opc.OPCPackage;
import org.apache.poi.util.RecordFormatException;
import org.apache.poi.xssf.extractor.XSSFEventBasedExcelExtractor;
import org.apache.poi.xssf.streaming.SXSSFWorkbook;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.apache.xmlbeans.XmlException;

public class POIXSSFFuzzer {
	public static void fuzzerInitialize() {
		POIFuzzer.adjustLimits();
	}

	public static void fuzzerTestOneInput(byte[] input) {
		try (XSSFWorkbook wb = new XSSFWorkbook(new ByteArrayInputStream(input))) {
			try (SXSSFWorkbook swb = new SXSSFWorkbook(wb)) {
				swb.write(NullOutputStream.INSTANCE);
			}
		} catch (IOException | POIXMLException | RecordFormatException | IllegalStateException |
				 OpenXML4JRuntimeException | IllegalArgumentException | IndexOutOfBoundsException e) {
			// expected here
		}

		try (OPCPackage pkg = OPCPackage.open(new ByteArrayInputStream(input))) {
			try (XSSFEventBasedExcelExtractor extractor = new XSSFEventBasedExcelExtractor(pkg)) {
				POIFuzzer.checkExtractor(extractor);
			}
		} catch (IOException | XmlException | OpenXML4JException | POIXMLException | RecordFormatException |
				IllegalStateException | IllegalArgumentException | IndexOutOfBoundsException e) {
			// expected
		}
	}
}
