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

import org.apache.poi.ooxml.POIXMLException;
import org.apache.poi.openxml4j.exceptions.OpenXML4JRuntimeException;
import org.apache.poi.util.RecordFormatException;
import org.apache.poi.xslf.usermodel.XMLSlideShow;
import org.apache.poi.xslf.usermodel.XSLFSlide;

import java.awt.Dimension;
import java.awt.Graphics2D;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.BufferUnderflowException;
import java.util.List;
import java.util.NoSuchElementException;

public class POIPPTX2PNGFuzzer {
    public static void fuzzerInitialize() {
        POIFuzzer.adjustLimits();
    }

    public static void fuzzerTestOneInput(byte[] input) {
        try (XMLSlideShow slideshow = new XMLSlideShow(new ByteArrayInputStream(input))) {
            Dimension pgsize = slideshow.getPageSize();
            List<XSLFSlide> slides = slideshow.getSlides();
            for (XSLFSlide slide : slides) {
                BufferedImage img = new BufferedImage(pgsize.width, pgsize.height, BufferedImage.TYPE_INT_ARGB);
                Graphics2D graphics = img.createGraphics();
                try {
                    slide.draw(graphics);
                } finally {
                    graphics.dispose();
                }
            }
        } catch (IOException | POIXMLException | IllegalArgumentException | IllegalStateException | 
                 IndexOutOfBoundsException | ArithmeticException | NegativeArraySizeException |
                 RecordFormatException | BufferUnderflowException | OpenXML4JRuntimeException |
                 UnsupportedOperationException | NoSuchElementException e) {
            // Expected exceptions on malformed input
        }
    }
}
