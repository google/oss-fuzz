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
import java.io.InputStream;

import org.apache.commons.io.output.NullPrintStream;
import org.apache.poi.examples.xssf.eventusermodel.XLSX2CSV;
import org.apache.poi.ooxml.POIXMLException;
import org.apache.poi.openxml4j.exceptions.OpenXML4JException;
import org.apache.poi.openxml4j.exceptions.OpenXML4JRuntimeException;
import org.apache.poi.openxml4j.opc.OPCPackage;
import org.apache.poi.util.RecordFormatException;
import org.xml.sax.SAXException;

public class XLSX2CSVFuzzer {
	public static void fuzzerInitialize() {
		POIFuzzer.adjustLimits();
	}

	public static void fuzzerTestOneInput(byte[] input) {
		try (InputStream in = new ByteArrayInputStream(input)) {
			OPCPackage p = OPCPackage.open(in);
			XLSX2CSV xlsx2csv = new XLSX2CSV(p, NullPrintStream.INSTANCE, 5);
			xlsx2csv.process();
		} catch (IOException | OpenXML4JException | SAXException |
				 POIXMLException | RecordFormatException |
				 IllegalStateException | IllegalArgumentException |
				 IndexOutOfBoundsException | OpenXML4JRuntimeException e) {
			// expected here
		}
	}
}