// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// You may not use this file except in compliance with the License.
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
///////////////////////////////////////////////////////////////////////////
import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.powsybl.commons.exceptions.UncheckedClassNotFoundException;
import com.powsybl.math.matrix.DenseMatrix;
import com.powsybl.math.matrix.Matrix;
import com.powsybl.math.matrix.MatrixException;
import com.powsybl.math.matrix.SparseMatrix;
import java.io.ByteArrayInputStream;
import java.io.UncheckedIOException;

public class MatrixFuzzer {

  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      // Prepare matrix with constructor
      Matrix matrix = null;
      if (data.consumeBoolean()) {
        matrix = new SparseMatrix(10, 10, new int[11], new int[11], new double[11]);
      } else {
        matrix = new DenseMatrix(10, 10, new double[100]);
      }
      matrix.reset();

      if (matrix == null) {
        return;
      }

      for (int j = 0; j < 10; j++) {
        for (int i = 0; i < 10; i++) {
          matrix.set(i, j, data.consumeDouble());
        }
      }

      // Fuzz operational methods
      matrix.decomposeLU();
      matrix.transpose().decomposeLU();
      matrix.toDense();
      matrix.toSparse();

      // Fuzz deserailisation
      Integer remaining = data.remainingBytes();
      byte[] eof = new byte[] {(byte) 0x04};
      byte[] random = new byte[remaining + eof.length];
      System.arraycopy(data.consumeRemainingAsBytes(), 0, random, 0, remaining);
      System.arraycopy(eof, 0, random, remaining, eof.length);
      ByteArrayInputStream input = new ByteArrayInputStream(random);
      Matrix other = SparseMatrix.read(input);
      matrix.times(other);
      matrix.add(other, 1, 1);
      matrix.equals(other);
    } catch (MatrixException
        | UncheckedIOException
        | IllegalArgumentException
        | UncheckedClassNotFoundException
        | ClassCastException e) {
      // Known exceptions
    } catch (NullPointerException e) {
      // Capture known NPE from malformed JSON
      if (!isExpected(e)) {
        throw e;
      }
    }
  }

  private static boolean isExpected(Throwable e) {
    String[] expectedString = {
      "java.util.Objects.requireNonNull",
      "Cannot invoke \"String.hashCode()\""
    };

    for (String expected : expectedString) {
      if (e.toString().contains(expected)) {
        return true;
      }
      for (StackTraceElement ste : e.getStackTrace()) {
        if (ste.toString().contains(expected)) {
          return true;
        }
      }
    }

    return false;
  }
}
