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

import org.apache.poi.hssf.extractor.OldExcelExtractor;
import org.apache.poi.hssf.record.RecordInputStream;
import org.apache.poi.poifs.filesystem.POIFSFileSystem;
import org.apache.poi.util.RecordFormatException;

public class POIOldExcelFuzzer {
	public static void fuzzerTestOneInput(byte[] input) {
		try {
			try (OldExcelExtractor extractor = new OldExcelExtractor(
							new POIFSFileSystem(new ByteArrayInputStream(input)).getRoot())) {
				POIFuzzer.checkExtractor(extractor);
			}
		} catch (IOException | IllegalArgumentException | RecordFormatException | IndexOutOfBoundsException |
				 RecordInputStream.LeftoverDataException | IllegalStateException | BufferUnderflowException |
				 NoSuchElementException e) {
			// expected here
		}
	}
}
