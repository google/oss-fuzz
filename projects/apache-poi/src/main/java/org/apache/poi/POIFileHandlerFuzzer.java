// Copyright 2026 Google LLC
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

import java.awt.AWTError;
import java.awt.geom.IllegalPathStateException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.BufferUnderflowException;
import java.util.NoSuchElementException;

import org.apache.poi.hslf.exceptions.HSLFException;
import org.apache.poi.hsmf.exceptions.ChunkNotFoundException;
import org.apache.poi.hssf.record.RecordInputStream;
import org.apache.poi.ooxml.POIXMLException;
import org.apache.poi.openxml4j.exceptions.OpenXML4JException;
import org.apache.poi.openxml4j.exceptions.OpenXML4JRuntimeException;
import org.apache.poi.ss.formula.FormulaParseException;
import org.apache.poi.ss.formula.eval.NotImplementedException;
import org.apache.poi.stress.FileHandler;
import org.apache.poi.stress.HEMFFileHandler;
import org.apache.poi.stress.HMEFFileHandler;
import org.apache.poi.stress.HPBFFileHandler;
import org.apache.poi.stress.HPSFFileHandler;
import org.apache.poi.stress.HSLFFileHandler;
import org.apache.poi.stress.HSMFFileHandler;
import org.apache.poi.stress.HSSFFileHandler;
import org.apache.poi.stress.HWMFFileHandler;
import org.apache.poi.stress.HWPFFileHandler;
import org.apache.poi.stress.OPCFileHandler;
import org.apache.poi.stress.OWPFFileHandler;
import org.apache.poi.stress.POIFSFileHandler;
import org.apache.poi.stress.XDGFFileHandler;
import org.apache.poi.stress.XSLFFileHandler;
import org.apache.poi.stress.XSSFBFileHandler;
import org.apache.poi.stress.XSSFFileHandler;
import org.apache.poi.stress.XWPFFileHandler;
import org.apache.poi.util.DocumentFormatException;
import org.apache.poi.util.RecordFormatException;
import org.apache.poi.xssf.binary.XSSFBParseException;
import org.apache.xmlbeans.XmlException;
import org.junit.platform.commons.util.ExceptionUtils;
import org.opentest4j.AssertionFailedError;
import org.opentest4j.TestAbortedException;
import org.xml.sax.SAXException;

/**
 * A fuzz target which uses the FileHandlers from integration testing of Apache POI
 * to execute a number of additional actions after successfully opening documents.
 *
 * This should extend coverage to some of the getters and other areas of POI which
 * are currently uncovered.
 */
public class POIFileHandlerFuzzer {
	private static final FileHandler[] HANDLERS = new FileHandler[] {
		new HMEFFileHandler(),
		new HPBFFileHandler(),
		new HPSFFileHandler(),
		new HSLFFileHandler(),
		new HSMFFileHandler(),
		new HSSFFileHandler(),
		new HEMFFileHandler(),
		new HWMFFileHandler(),
		new HWPFFileHandler(),
		new OPCFileHandler(),
		new OWPFFileHandler(),
		new POIFSFileHandler(),
		new XDGFFileHandler(),
		new XSLFFileHandler(),
		new XSSFBFileHandler(),
		new XSSFFileHandler(),
		new XWPFFileHandler(),
	};

	public static void fuzzerInitialize() {
		POIFuzzer.adjustLimits();
	}

	public static void fuzzerTestOneInput(byte[] input) throws Exception {
		ByteArrayInputStream stream = new ByteArrayInputStream(input);
		for (FileHandler handler : HANDLERS) {
			stream.mark(input.length);

			try {
				handler.handleFile(stream, "dummy-file-name");
			} catch (POIXMLException | IOException | SAXException | XmlException | HSLFException |
					 IllegalArgumentException | IllegalStateException | IndexOutOfBoundsException | NoSuchElementException |
					 UnsupportedOperationException | NegativeArraySizeException | BufferUnderflowException |
					 ChunkNotFoundException | RecordInputStream.LeftoverDataException | RecordFormatException |
					 OpenXML4JException | OpenXML4JRuntimeException | DocumentFormatException | XSSFBParseException |
					 // some FileHandlers perform checks via assertions, so we expect this type of exception as well
					 AssertionFailedError | TestAbortedException |
					 NotImplementedException | FormulaParseException | IllegalPathStateException
					e) {
				// expected here
			} catch (AWTError e) {
				// POI cannot fix it if there is no DISPLAY
				if (!ExceptionUtils.readStackTrace(e).contains("Can't connect to X11 window server")) {
					throw e;
				}
			} catch (InternalError e) {
				// POI cannot fix it if the font-system is not fully installed, so let's ignore
				// this for fuzzing
				if (!ExceptionUtils.readStackTrace(e).contains("Fontconfig head is null")) {
					throw e;
				}
			}

			stream.reset();
		}
	}
}
