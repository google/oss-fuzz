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

import com.code_intelligence.jazzer.api.FuzzedDataProvider;

import java.io.IOException;
import java.io.ByteArrayInputStream;

import java.util.List;

import net.lingala.zip4j.io.inputstream.ZipInputStream;
import net.lingala.zip4j.model.LocalFileHeader;
import net.lingala.zip4j.model.ExtraDataRecord;
import net.lingala.zip4j.model.AESExtraDataRecord;
import net.lingala.zip4j.model.enums.CompressionMethod;
import net.lingala.zip4j.model.enums.EncryptionMethod;
import net.lingala.zip4j.model.Zip64ExtendedInfo;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;

public class Zip4jFuzzer {
	public static void fuzzerTestOneInput(FuzzedDataProvider data) {

		ZipInputStream v0 = null;
		LocalFileHeader v1 = null;
		AESExtraDataRecord v2 = null;
		CompressionMethod v3 = null;
		EncryptionMethod v4 = null;
		List<ExtraDataRecord> v5 = null;
		Zip64ExtendedInfo v6 = null;

		try {
			v0 = new ZipInputStream(new ByteArrayInputStream(data.consumeRemainingAsBytes()));

			if (v0 != null) {

				while (true) {

					v1 = v0.getNextEntry();
					if (v1 ==  null)
						break;
					else {

						v1.isDirectory();
						v1.isEncrypted();

						v2 = v1.getAesExtraDataRecord();
						if (v2 != null) {
							v2.getCompressionMethod();
							v2.getDataSize();
						}

						v3 = v1.getCompressionMethod();
						if (v3 != null) {
							v3.getCode();
						}

						v4 = v1.getEncryptionMethod();
						v5 = v1.getExtraDataRecords();
						if (v5 != null) {
							for (ExtraDataRecord v7 : v5) {
								v7.getData();
								v7.getHeader();
								v7.getSizeOfData();
							}
						}

						v6 = v1.getZip64ExtendedInfo();
						if (v6 != null) {
							v6.getCompressedSize();
							v6.getUncompressedSize();
						}

					}

				}

			}

		} catch (IOException e) {
			return;
		}
	}
}
