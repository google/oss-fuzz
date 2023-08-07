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
import org.apache.poi.hwpf.HWPFDocument;
import org.apache.poi.hwpf.extractor.WordExtractor;
import org.apache.poi.poifs.filesystem.POIFSFileSystem;
import org.apache.poi.util.DocumentFormatException;
import org.apache.poi.util.RecordFormatException;

public class POIHWPFFuzzer {
	public static void fuzzerTestOneInput(byte[] input) {
		try (HWPFDocument doc = new HWPFDocument(new ByteArrayInputStream(input))) {
			doc.write(NullOutputStream.INSTANCE);
		} catch (IOException | IllegalArgumentException | IndexOutOfBoundsException | BufferUnderflowException |
				NoSuchElementException | RecordFormatException | IllegalStateException |
				UnsupportedOperationException | NegativeArraySizeException e) {
			// expected here
		}

		try {
			try (WordExtractor extractor = new WordExtractor(
							new POIFSFileSystem(new ByteArrayInputStream(input)).getRoot())) {
				POIFuzzer.checkExtractor(extractor);
			}
		} catch (IOException | IllegalArgumentException | IndexOutOfBoundsException | BufferUnderflowException |
				NoSuchElementException | RecordFormatException | IllegalStateException |
				DocumentFormatException | UnsupportedOperationException | NegativeArraySizeException e) {
			// expected here
		}
	}
}
