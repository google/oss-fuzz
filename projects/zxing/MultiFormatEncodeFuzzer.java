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

import com.google.zxing.BarcodeFormat;
import com.google.zxing.MultiFormatWriter;
import com.google.zxing.MultiFormatReader;
import com.google.zxing.aztec.encoder.AztecCode;
import com.google.zxing.aztec.AztecReader;
import com.google.zxing.datamatrix.DataMatrixReader;
import com.google.zxing.maxicode.MaxiCodeReader;
import com.google.zxing.oned.MultiFormatOneDReader;
import com.google.zxing.pdf417.PDF417Reader;
import com.google.zxing.qrcode.QRCodeReader;
import com.google.zxing.oned.CodaBarReader;
import com.google.zxing.oned.Code128Reader;
import com.google.zxing.oned.Code39Reader;
import com.google.zxing.oned.Code93Reader;
import com.google.zxing.oned.EAN13Reader;
import com.google.zxing.oned.EAN8Reader;
import com.google.zxing.oned.ITFReader;
import com.google.zxing.oned.UPCAReader;
import com.google.zxing.oned.UPCEReader;
import com.google.zxing.pdf417.PDF417Reader;
import com.google.zxing.qrcode.QRCodeReader;

import java.util.EnumMap;
import java.util.Map;

import javax.naming.NameNotFoundException;

import com.google.zxing.Reader;
import com.google.zxing.Binarizer;
import com.google.zxing.BinaryBitmap;
import com.google.zxing.WriterException;
import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.common.BitArray;
import com.google.zxing.NotFoundException;
import com.google.zxing.FormatException;
import com.google.zxing.ChecksumException;
import com.google.zxing.LuminanceSource;
import com.google.zxing.Result;
import com.google.zxing.pdf417.PDF417Writer;

import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel;
import com.google.zxing.qrcode.decoder.Mode;
import com.google.zxing.qrcode.encoder.QRCode;

import com.google.zxing.datamatrix.encoder.HighLevelEncoder;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;

public final class MultiFormatEncodeFuzzer {

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        int width = data.consumeInt(100, 200);
        int height = data.consumeInt(100, 200);
        BarcodeFormat format = data.pickValue(BarcodeFormat.values());
        String originalData = data.consumeRemainingAsAsciiString();

        BitMatrix matrix;
        try {
            matrix = new MultiFormatWriter().encode(originalData, format, width, height);
        } catch (WriterException | IllegalArgumentException e) {
            return;
        }

        BinaryBitmap bitmap = null;
        Result result;
        try {
            bitmap = new BinaryBitmap(new TrivialBinarizer(matrix));
            result = getReader(format).decode(bitmap);
        } catch (NotFoundException | ChecksumException | FormatException e) {
            throw new IllegalStateException("Failed to recover\n" + originalData + "\nencoded with " + format + " in "
                    + width + "x" + height + "\n\n" + matrix.toString() + "\n\n" + bitmap.toString(), e);
        }
        String decodedData = result.getText();
        if (!decodedData.equals(originalData)) {
            throw new IllegalStateException(
                    "Failed to recover\n" + originalData + "\nencoded with " + format + " in " + width + "x" + height
                            + ", got:\n" + decodedData + "\n\n" + matrix.toString() + "\n\n" + bitmap.toString());
        }
    }

    private static Reader getReader(BarcodeFormat format) {
        switch (format) {
            case EAN_8:
                return new EAN8Reader();
            case UPC_E:
                return new UPCEReader();
            case EAN_13:
                return new EAN13Reader();
            case UPC_A:
                return new UPCAReader();
            case QR_CODE:
                return new QRCodeReader();
            case CODE_39:
                return new Code39Reader();
            case CODE_93:
                return new Code93Reader();
            case CODE_128:
                return new Code128Reader();
            case ITF:
                return new ITFReader();
            case PDF_417:
                return new PDF417Reader();
            case CODABAR:
                return new CodaBarReader();
            case DATA_MATRIX:
                return new DataMatrixReader();
            case AZTEC:
                return new AztecReader();
            default:
                throw new IllegalArgumentException("No encoder available for format " + format);
        }
    }

    private static final class TrivialBinarizer extends Binarizer {
        private final BitMatrix matrix;

        public TrivialBinarizer(BitMatrix matrix) {
            super(new TrivialLuminanceSource(matrix));
            this.matrix = matrix;
        }

        public BitArray getBlackRow(int y, BitArray row) throws NotFoundException {
            return matrix.getRow(y, row);
        }

        public BitMatrix getBlackMatrix() throws NotFoundException {
            return matrix;
        }

        public Binarizer createBinarizer(LuminanceSource source) {
            return new TrivialBinarizer(matrix);
        }
    }

    private static final class TrivialLuminanceSource extends LuminanceSource {
        private final BitMatrix matrix;

        public TrivialLuminanceSource(BitMatrix matrix) {
            super(matrix.getWidth(), matrix.getHeight());
            this.matrix = matrix;
        }

        public byte[] getRow(int y, byte[] row) {
            if (row.length != matrix.getWidth()) {
                row = new byte[matrix.getWidth()];
            }
            BitArray bitRow = matrix.getRow(y, null);
            for (int i = 0; i < matrix.getWidth(); i++) {
                if (bitRow.get(i)) {
                    row[i] = 0;
                } else {
                    row[i] = (byte) 255;
                }
            }
            return row;
        }

        public byte[] getMatrix() {
            byte[] bytes = new byte[matrix.getWidth() * matrix.getHeight()];
            for (int x = 0; x < matrix.getWidth(); x++) {
                for (int y = 0; y < matrix.getHeight(); y++) {
                    if (!matrix.get(x, y))
                        bytes[x + y * matrix.getWidth()] = (byte) 255;
                }
            }
            return bytes;
        }
    }
}
