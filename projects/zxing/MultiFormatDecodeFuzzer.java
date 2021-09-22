// Copyright 2021 Google LLC
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

import com.google.zxing.BinaryBitmap;
import com.google.zxing.BufferedImageLuminanceSource;
import com.google.zxing.MultiFormatReader;
import com.google.zxing.ReaderException;
import com.google.zxing.Result;
import com.google.zxing.common.HybridBinarizer;

import javax.imageio.ImageIO;
import java.io.IOException;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;

public final class MultiFormatDecodeFuzzer {
    private static MultiFormatReader barcodeReader = new MultiFormatReader();

    public static void fuzzerInitialize() {
    }

    public static void fuzzerTestOneInput(byte[] input) {
        BufferedImage image;
        try {
            image = ImageIO.read(new ByteArrayInputStream(input));
        } catch (IOException e) {
            return;
        }
        if (image == null)
            return;
        if ((long) image.getHeight() * (long) image.getWidth() > 10000000)
            return;

        BufferedImageLuminanceSource source = new BufferedImageLuminanceSource(image);
        BinaryBitmap bitmap = new BinaryBitmap(new HybridBinarizer(source));
        try {
            Result result = barcodeReader.decode(bitmap);
            result.getText();
            result.getResultMetadata();
        } catch (ReaderException ignored) {
        }
    }
}
