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
import org.apache.poi.hslf.exceptions.HSLFException;
import org.apache.poi.hssf.extractor.ExcelExtractor;
import org.apache.poi.hssf.record.RecordInputStream;
import org.apache.poi.hssf.usermodel.HSSFWorkbook;
import org.apache.poi.poifs.filesystem.POIFSFileSystem;
import org.apache.poi.util.RecordFormatException;

public class POIHSSFFuzzer {
	public static void fuzzerTestOneInput(byte[] input) {
		try (HSSFWorkbook wb = new HSSFWorkbook(new ByteArrayInputStream(input))) {
			wb.write(NullOutputStream.INSTANCE);
		} catch (IOException | IllegalArgumentException | RecordFormatException | IllegalStateException |
				 IndexOutOfBoundsException | RecordInputStream.LeftoverDataException |
				 BufferUnderflowException | UnsupportedOperationException | NoSuchElementException |
				NegativeArraySizeException e) {
			// expected here
		}

		try {
			try (ExcelExtractor extractor = new ExcelExtractor(
							new POIFSFileSystem(new ByteArrayInputStream(input)).getRoot())) {
				POIFuzzer.checkExtractor(extractor);
			}
		} catch (UnsatisfiedLinkError e) {
			// only allow one missing library related to Font-handling
			// we cannot install JDK font packages in oss-fuzz images currently
			// see https://github.com/google/oss-fuzz/issues/7380
			if (!e.getMessage().contains("libawt_xawt.so")) {
				throw e;
			}
		} catch (IOException | IllegalArgumentException | RecordFormatException | IllegalStateException |
				 IndexOutOfBoundsException | RecordInputStream.LeftoverDataException |
				 BufferUnderflowException | UnsupportedOperationException | NoSuchElementException |
				 NegativeArraySizeException | HSLFException e) {
			// expected here
		}
	}
}
