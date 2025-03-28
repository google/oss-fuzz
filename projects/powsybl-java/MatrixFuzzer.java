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
      int row = data.consumeInt(1, 10);
      int col = data.consumeInt(1, 10);

      // Prepare matrix with constructor
      Matrix matrix = null;
      if (data.consumeBoolean()) {
        matrix =
            new SparseMatrix(row, col, new int[col + 1], new int[row + 1], new double[row + 1]);
      } else {
        matrix = new DenseMatrix(row, col, new double[row * col]);
      }

      if (matrix == null) {
        return;
      }

      for (int j = 0; j < col; j++) {
        for (int i = 0; i < row; i++) {
          double value = data.consumeDouble();
          matrix.set(i, j, data.consumeDouble());
        }
      }
      matrix.reset();

      // Fuzz operational methods
      matrix.decomposeLU();
      matrix.transpose().decomposeLU();
      matrix.toDense();
      matrix.toSparse();

      // Fuzz deserailisation
      ByteArrayInputStream input = new ByteArrayInputStream(data.consumeRemainingAsBytes());
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
    }
  }
}
