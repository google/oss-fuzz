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

import org.apache.poi.hsmf.MAPIMessage;
import org.apache.poi.hsmf.datatypes.AttachmentChunks;
import org.apache.poi.hsmf.datatypes.DirectoryChunk;
import org.apache.poi.hsmf.exceptions.ChunkNotFoundException;
import org.apache.poi.util.RecordFormatException;

public class POIHSMFFuzzer {
	public static void fuzzerTestOneInput(byte[] input) {
		try (MAPIMessage mapi = new MAPIMessage(new ByteArrayInputStream(input))) {
			mapi.getAttachmentFiles();
			mapi.getDisplayBCC();
			mapi.getMessageDate();

			AttachmentChunks[] attachments = mapi.getAttachmentFiles();
			for (AttachmentChunks attachment : attachments) {
				DirectoryChunk chunkDirectory = attachment.getAttachmentDirectory();
				if (chunkDirectory != null) {
					MAPIMessage attachmentMSG = chunkDirectory.getAsEmbeddedMessage();
					attachmentMSG.getTextBody();
				}
			}
		} catch (IOException | ChunkNotFoundException | IllegalArgumentException |
				 RecordFormatException | IndexOutOfBoundsException | NoSuchElementException |
				 BufferUnderflowException | IllegalStateException e) {
			// expected here
		}
	}
}
