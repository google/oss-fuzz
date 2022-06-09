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

import java.io.InputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.ByteArrayInputStream;

import com.github.junrar.Archive;
import com.github.junrar.rarfile.FileHeader;
import com.github.junrar.exception.RarException;
import com.github.junrar.io.SeekableReadOnlyByteChannel;
import com.github.junrar.rarfile.MainHeader;
import com.github.junrar.volume.Volume;

public class JunrarFuzzer {
	public static void fuzzerTestOneInput(FuzzedDataProvider data) {

		try {
			InputStream inputStream = new ByteArrayInputStream(data.consumeRemainingAsBytes());
			Archive v0 = null;
			FileHeader v1 = null;
			SeekableReadOnlyByteChannel v2 = null;
			MainHeader v3 = null;
			Volume v4 = null;

			v0 = new Archive(inputStream);
			v2 = v0.getChannel();
			if (v2 != null) {
				v2.getPosition();
			}

			v0.getFileHeaders();
			v0.getHeaders();

			v3 = v0.getMainHeader();
			if (v3 != null) {
				v3.getEncryptVersion();
				v3.isEncrypted();
				//v3.print();
			}

			v4 = v0.getVolume();
			if (v4 != null) {
				v4.getChannel();
				v4.getLength();
			}

			v0.isEncrypted();

			while (true) {
				v1 = v0.nextFileHeader();
				if (v1 == null) {
					break;
				}

				v1.getCTime();
				v1.hasVolumeNumber();
				v1.isSubBlock();

				v0.extractFile(v1, OutputStream.nullOutputStream()); 
			}

		} catch (IOException e1) {
		} catch (RarException e2) {
			return;
		}
	}
}
