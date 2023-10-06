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

import java.nio.charset.StandardCharsets;

import java.io.ByteArrayInputStream;
import java.io.UncheckedIOException;

import org.apache.commons.geometry.io.core.input.StreamGeometryInput;
import org.apache.commons.geometry.io.euclidean.threed.BoundaryReadHandler3D;
import org.apache.commons.geometry.io.euclidean.threed.stl.StlBoundaryReadHandler3D;
import org.apache.commons.numbers.core.Precision;

public class GeometryStlTextFuzzer {
    public static void fuzzerTestOneInput(final byte[] data) {
        // prepend the "solid" STL keyword to the input to ensure it is interpreted
        // as text STL input
        final byte[] dataWithPrefix = join("solid ".getBytes(StandardCharsets.US_ASCII), data);

        try {
            final BoundaryReadHandler3D handler = new StlBoundaryReadHandler3D();

            final Precision.DoubleEquivalence precision = Precision.doubleEquivalenceOfEpsilon(1e-20);

            // check standard read
            handler.read(new StreamGeometryInput(new ByteArrayInputStream(dataWithPrefix)), precision);

            // check mesh read
            handler.readTriangleMesh(new StreamGeometryInput(new ByteArrayInputStream(dataWithPrefix)), precision);
        } catch (UncheckedIOException | IllegalArgumentException | IllegalStateException ignored) {
            // expected exception types; ignore
        }
    }

    private static byte[] join(final byte[] a, final byte[] b) {
        final byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);

        return result;
    }
}
