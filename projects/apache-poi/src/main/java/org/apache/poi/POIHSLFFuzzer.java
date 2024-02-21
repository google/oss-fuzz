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
import org.apache.poi.hslf.usermodel.HSLFShape;
import org.apache.poi.hslf.usermodel.HSLFSlideShow;
import org.apache.poi.hslf.usermodel.HSLFSlideShowImpl;
import org.apache.poi.hslf.usermodel.HSLFTextParagraph;
import org.apache.poi.ooxml.POIXMLException;
import org.apache.poi.poifs.filesystem.POIFSFileSystem;
import org.apache.poi.sl.extractor.SlideShowExtractor;
import org.apache.poi.sl.usermodel.SlideShowFactory;
import org.apache.poi.util.RecordFormatException;

public class POIHSLFFuzzer {
	public static void fuzzerInitialize() {
		POIFuzzer.adjustLimits();
	}

	public static void fuzzerTestOneInput(byte[] input) {
		try (HSLFSlideShow slides = new HSLFSlideShow(new ByteArrayInputStream(input))) {
			slides.write(NullOutputStream.INSTANCE);
		} catch (IOException | IllegalArgumentException | RecordFormatException |
				 IllegalStateException | HSLFException | IndexOutOfBoundsException |
				 BufferUnderflowException | POIXMLException | NoSuchElementException e) {
			// expected here
		}

		try (HSLFSlideShowImpl slides = new HSLFSlideShowImpl(new ByteArrayInputStream(input))) {
			slides.write(NullOutputStream.INSTANCE);
		} catch (IOException | IllegalArgumentException | RecordFormatException |
				 IllegalStateException | HSLFException | IndexOutOfBoundsException |
				 BufferUnderflowException | POIXMLException | NoSuchElementException e) {
			// expected here
		}

		try {
			try (SlideShowExtractor<HSLFShape, HSLFTextParagraph> extractor =
					new SlideShowExtractor<>((HSLFSlideShow) SlideShowFactory.create(
							new POIFSFileSystem(new ByteArrayInputStream(input)).getRoot()))) {
				POIFuzzer.checkExtractor(extractor);
			}
		} catch (IOException | IllegalArgumentException | RecordFormatException |
				 IllegalStateException | HSLFException | IndexOutOfBoundsException |
				 BufferUnderflowException | POIXMLException | NoSuchElementException e) {
			// expected here
		}
	}
}
