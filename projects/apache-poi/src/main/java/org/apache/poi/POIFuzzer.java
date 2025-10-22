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
import java.nio.BufferUnderflowException;
import java.util.NoSuchElementException;

import org.apache.commons.io.output.NullOutputStream;
import org.apache.poi.extractor.ExtractorFactory;
import org.apache.poi.extractor.POIOLE2TextExtractor;
import org.apache.poi.extractor.POITextExtractor;
import org.apache.poi.hslf.exceptions.HSLFException;
import org.apache.poi.hssf.record.RecordFactory;
import org.apache.poi.hssf.record.RecordInputStream;
import org.apache.poi.ooxml.POIXMLException;
import org.apache.poi.ooxml.extractor.POIXMLPropertiesTextExtractor;
import org.apache.poi.ooxml.extractor.POIXMLTextExtractor;
import org.apache.poi.openxml4j.exceptions.OpenXML4JRuntimeException;
import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.ss.usermodel.Sheet;
import org.apache.poi.ss.usermodel.Workbook;
import org.apache.poi.ss.usermodel.WorkbookFactory;
import org.apache.poi.util.DocumentFormatException;
import org.apache.poi.util.RecordFormatException;

/**
 * This class provides a simple target for fuzzing Apache POI with Jazzer.
 *
 * It uses the byte-array to call various method which parse the various
 * supported file-formats.
 *
 * It catches all exceptions that are currently expected.
 */
public class POIFuzzer {
	public static void fuzzerInitialize() {
		adjustLimits();
	}

	public static void fuzzerTestOneInput(byte[] input) {
		// try to invoke various methods which parse documents/workbooks/slide-shows/...
		// all of these catch expected exceptions and thus any failure indicates something
		// that we should take a look at

		fuzzAny(input);

		POIHDGFFuzzer.fuzzerTestOneInput(input);

		POIHMEFFuzzer.fuzzerTestOneInput(input);

		POIHPBFFuzzer.fuzzerTestOneInput(input);

		POIHPSFFuzzer.fuzzerTestOneInput(input);

		POIHSLFFuzzer.fuzzerTestOneInput(input);

		POIHSMFFuzzer.fuzzerTestOneInput(input);

		POIHSSFFuzzer.fuzzerTestOneInput(input);

		POIHWPFFuzzer.fuzzerTestOneInput(input);

		POIOldExcelFuzzer.fuzzerTestOneInput(input);

		POIVisioFuzzer.fuzzerTestOneInput(input);

		XLSX2CSVFuzzer.fuzzerTestOneInput(input);

		POIXSLFFuzzer.fuzzerTestOneInput(input);

		POIXSSFFuzzer.fuzzerTestOneInput(input);

		POIXWPFFuzzer.fuzzerTestOneInput(input);
	}

	public static void fuzzAny(byte[] input) {
		try (Workbook wb = WorkbookFactory.create(new ByteArrayInputStream(input))) {
			for (Sheet sheet : wb) {
				for (Row row : sheet) {
					for (Cell cell : row) {
						cell.getAddress();
						cell.getCellType();
					}
				}
			}

			wb.write(NullOutputStream.INSTANCE);
		} catch (IOException | POIXMLException | IllegalArgumentException | RecordFormatException |
				 IndexOutOfBoundsException | HSLFException | RecordInputStream.LeftoverDataException |
				 IllegalStateException | BufferUnderflowException | OpenXML4JRuntimeException |
				UnsupportedOperationException | NoSuchElementException | NegativeArraySizeException e) {
			// expected here
		}

		ExtractorFactory.setThreadPrefersEventExtractors(true);
		checkExtractor(input);
		ExtractorFactory.setAllThreadsPreferEventExtractors(false);
		checkExtractor(input);
	}

	public static void checkExtractor(byte[] input) {
		try (POITextExtractor extractor = ExtractorFactory.createExtractor(new ByteArrayInputStream(input))) {
			checkExtractor(extractor);
		} catch (IOException | POIXMLException | IllegalArgumentException | RecordFormatException |
				 IndexOutOfBoundsException | HSLFException | RecordInputStream.LeftoverDataException |
				 NoSuchElementException | IllegalStateException | ArithmeticException |
				 BufferUnderflowException | UnsupportedOperationException | DocumentFormatException |
				NegativeArraySizeException e) {
			// expected here
		}
	}

	@SuppressWarnings("DuplicatedCode")
	public static void checkExtractor(POITextExtractor extractor) throws IOException {
		extractor.getDocument();
		extractor.getFilesystem();
		try {
			extractor.getMetadataTextExtractor();
		} catch (IllegalStateException e) {
			// can happen here
		}
		try {
			extractor.getText();
		} catch (OpenXML4JRuntimeException e) {
			// can happen here
		}

		if (extractor instanceof POIOLE2TextExtractor) {
			POIOLE2TextExtractor ole2Extractor = (POIOLE2TextExtractor) extractor;
			ole2Extractor.getRoot();
			ole2Extractor.getSummaryInformation();
			ole2Extractor.getDocSummaryInformation();

			POITextExtractor[] embedded = ExtractorFactory.getEmbeddedDocsTextExtractors(ole2Extractor);
			for (POITextExtractor poiTextExtractor : embedded) {
				poiTextExtractor.getText();
				poiTextExtractor.getDocument();
				poiTextExtractor.getFilesystem();
				POITextExtractor metaData = poiTextExtractor.getMetadataTextExtractor();
				metaData.getFilesystem();
				metaData.getText();
			}
		} else if (extractor instanceof POIXMLTextExtractor) {
			POIXMLTextExtractor xmlExtractor = (POIXMLTextExtractor) extractor;
			xmlExtractor.getCoreProperties();
			xmlExtractor.getCustomProperties();
			xmlExtractor.getExtendedProperties();
			POIXMLPropertiesTextExtractor metaData = xmlExtractor.getMetadataTextExtractor();
			metaData.getFilesystem();
			metaData.getText();

			xmlExtractor.getPackage();
		}
	}

	static void adjustLimits() {
		// reduce limits so we do not get OOMs with the Xmx settings
		// that are used for the fuzzing runs
		RecordFactory.setMaxNumberOfRecords(100_000);
	}
}
