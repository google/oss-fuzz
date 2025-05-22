// Copyright 2022 Google LLC
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
import java.io.ByteArrayInputStream;
import java.io.IOException;

import org.apache.arrow.memory.BufferAllocator;
import org.apache.arrow.memory.RootAllocator;
import org.apache.arrow.vector.VectorSchemaRoot;
import org.apache.arrow.vector.ipc.ArrowStreamReader;
import org.apache.arrow.vector.util.ValueVectorUtility;

public class FuzzIpcStream {

    public static void fuzzerTestOneInput(byte[] data) {
        BufferAllocator allocator = new RootAllocator(Integer.MAX_VALUE);
        try (ArrowStreamReader reader = new ArrowStreamReader(new ByteArrayInputStream(data), allocator)) {
            VectorSchemaRoot root = reader.getVectorSchemaRoot();

            // validate schema
            ValueVectorUtility.validate(root);

            while (reader.loadNextBatch()) {
                ValueVectorUtility.validateFull(root);
            }
        } catch (IOException e) {}
    }
}
