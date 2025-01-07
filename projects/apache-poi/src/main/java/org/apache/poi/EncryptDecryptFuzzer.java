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

import static org.apache.poi.poifs.crypt.Decryptor.DEFAULT_POIFS_ENTRY;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.util.Arrays;

import org.apache.commons.io.output.UnsynchronizedByteArrayOutputStream;
import org.apache.poi.poifs.crypt.Decryptor;
import org.apache.poi.poifs.crypt.EncryptionInfo;
import org.apache.poi.poifs.crypt.EncryptionMode;
import org.apache.poi.poifs.crypt.Encryptor;
import org.apache.poi.poifs.filesystem.DocumentInputStream;
import org.apache.poi.poifs.filesystem.POIFSFileSystem;
import org.apache.poi.util.HexDump;
import org.apache.poi.util.IOUtils;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;

public class EncryptDecryptFuzzer {
	public static void fuzzerInitialize() {
		POIFuzzer.adjustLimits();
	}

	public static void fuzzerTestOneInput(FuzzedDataProvider data) throws IOException, GeneralSecurityException {
		try {
			EncryptionMode encryptionMode = EncryptionMode.values()[(data.consumeInt(0, EncryptionMode.values().length - 1))];
			String password = data.consumeString(20);
			byte[] testData = data.consumeRemainingAsBytes();

			EncryptionInfo infoEnc = new EncryptionInfo(encryptionMode);
			Encryptor enc = infoEnc.getEncryptor();
			enc.confirmPassword(password);

			byte[] encData;
			byte[] encDocument;
			try (POIFSFileSystem fsEnc = new POIFSFileSystem()) {
				try (OutputStream os = enc.getDataStream(fsEnc)) {
					os.write(testData);
				}

				UnsynchronizedByteArrayOutputStream bos = UnsynchronizedByteArrayOutputStream.builder().get();
				fsEnc.writeFilesystem(bos);

				bos.close();
				encData = bos.toByteArray();

				DocumentInputStream dis = fsEnc.getRoot().createDocumentInputStream(DEFAULT_POIFS_ENTRY);
				/*long _length =*/
				dis.readLong();
				encDocument = IOUtils.toByteArray(dis);
			}

			byte[] actualData;
			try (POIFSFileSystem fsDec = new POIFSFileSystem(new ByteArrayInputStream(encData))) {
				EncryptionInfo infoDec = new EncryptionInfo(fsDec);
				Decryptor dec = infoDec.getDecryptor();
				if (!dec.verifyPassword(password)) {
					throw new IllegalStateException("Could not verify password when decrypting " + password + "\n" +
							HexDump.dump(testData, 0, 0) + " and encrypted \n" +
							HexDump.dump(encDocument, 0, 0) + " full encrypted \n" +
							HexDump.dump(encData, 0, 0));
				}
				InputStream is = dec.getDataStream(fsDec);

				actualData = IOUtils.toByteArray(is);
				is.close();
			}

			// input-data and resulting decrypted data should be equal
			if (!Arrays.equals(testData, actualData)) {
				throw new IllegalStateException("Resulting array was not equal to input-array, "
						+ "having " + testData.length + " bytes, had actual length " + actualData.length + " and expected \n" +
						HexDump.dump(testData, 0, 0) + " and actual \n" +
						HexDump.dump(actualData, 0, 0) + " encrypted \n" +
						HexDump.dump(encDocument, 0, 0) + " full encrypted \n" +
						HexDump.dump(encData, 0, 0));
			}
		} catch (IOException | EncryptedDocumentException e) {
			// expected, e.g. when something is not supported
		}
	}
}
