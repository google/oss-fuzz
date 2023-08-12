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
import org.apache.poi.hdgf.HDGFDiagram;
import org.apache.poi.hdgf.extractor.VisioTextExtractor;
import org.apache.poi.poifs.filesystem.POIFSFileSystem;
import org.apache.poi.util.RecordFormatException;

public class POIHDGFFuzzer {
	public static void fuzzerTestOneInput(byte[] input) {
		try (HDGFDiagram visio = new HDGFDiagram(new POIFSFileSystem(new ByteArrayInputStream(input)))) {
			visio.write(NullOutputStream.INSTANCE);

			try (VisioTextExtractor extractor = new VisioTextExtractor(visio)) {
				POIFuzzer.checkExtractor(extractor);
			}
		} catch (IOException | IllegalArgumentException | IllegalStateException | RecordFormatException |
				 IndexOutOfBoundsException | BufferUnderflowException | ArithmeticException |
				 NoSuchElementException e) {
			// expected here
		}
	}
}
