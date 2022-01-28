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
import org.apache.arrow.vector.ipc.ArrowFileReader;
import org.apache.arrow.vector.ipc.InvalidArrowFileException;
import org.apache.arrow.vector.ipc.SeekableReadChannel;
import org.apache.arrow.vector.util.ByteArrayReadableSeekableByteChannel;
import org.apache.arrow.vector.util.ValueVectorUtility;

public class FuzzIpcFile {

    public static void fuzzerTestOneInput(byte[] data) {
        BufferAllocator allocator = new RootAllocator(Integer.MAX_VALUE);
        try (SeekableReadChannel channel = new SeekableReadChannel(new ByteArrayReadableSeekableByteChannel(data));
            ArrowFileReader reader = new ArrowFileReader(channel, allocator)) {
            VectorSchemaRoot root = reader.getVectorSchemaRoot();

            // validate schema
            ValueVectorUtility.validate(root);

            while (reader.loadNextBatch()) {
                ValueVectorUtility.validateFull(root);
            }
        } catch (IOException | InvalidArrowFileException e) {}
    }
}
