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
import org.apache.poi.EmptyFileException;
import org.apache.poi.UnsupportedFileFormatException;
import org.apache.poi.ooxml.POIXMLException;
import org.apache.poi.openxml4j.exceptions.InvalidFormatException;
import org.apache.poi.openxml4j.exceptions.OpenXML4JException;
import org.apache.poi.openxml4j.exceptions.OpenXML4JRuntimeException;
import org.apache.poi.openxml4j.opc.OPCPackage;
import org.apache.poi.util.RecordFormatException;
import org.apache.poi.xslf.extractor.XSLFExtractor;
import org.apache.poi.xslf.usermodel.XMLSlideShow;
import org.apache.poi.xslf.usermodel.XSLFSlideShow;
import org.apache.xmlbeans.XmlException;

public class POIXSLFFuzzer {
	public static void fuzzerTestOneInput(byte[] input) {
		try (XMLSlideShow slides = new XMLSlideShow(new ByteArrayInputStream(input))) {
			slides.write(NullOutputStream.INSTANCE);
		} catch (IOException | EmptyFileException | UnsupportedFileFormatException | POIXMLException |
				 RecordFormatException | OpenXML4JRuntimeException e) {
			// expected here
		}

		try (OPCPackage pkg = OPCPackage.open(new ByteArrayInputStream(input))) {
			try (XSLFSlideShow slides = new XSLFSlideShow(pkg)) {
				slides.write(NullOutputStream.INSTANCE);
			}
		} catch (IOException | OpenXML4JException | XmlException | IllegalArgumentException | POIXMLException |
				 RecordFormatException | IllegalStateException | OpenXML4JRuntimeException e) {
			// expected here
		}

		try (OPCPackage pkg = OPCPackage.open(new ByteArrayInputStream(input))) {
			try (XSLFExtractor extractor = new XSLFExtractor(new XMLSlideShow(pkg))) {
				POIFuzzer.checkExtractor(extractor);
			}
		} catch (IOException | InvalidFormatException | POIXMLException | IllegalArgumentException |
				RecordFormatException | IllegalStateException e) {
			// expected
		}
	}
}
