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
import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import org.apache.commons.io.filefilter.CanExecuteFileFilter;
import org.apache.commons.io.filefilter.CanReadFileFilter;
import org.apache.commons.io.filefilter.CanWriteFileFilter;
import org.apache.commons.io.filefilter.EmptyFileFilter;
import org.apache.commons.io.filefilter.FileEqualsFileFilter;
import org.apache.commons.io.filefilter.FileFilterUtils;
import org.apache.commons.io.filefilter.HiddenFileFilter;
import org.apache.commons.io.filefilter.IOFileFilter;
import org.apache.commons.io.filefilter.TrueFileFilter;
import org.apache.commons.io.filefilter.WildcardFileFilter;

/**
 * This fuzzer targets the accept method of different FileFilter implementation classes in the
 * filefilter package.
 */
public class FileFilterFuzzer {
  private static File file;

  public static void fuzzerInitialize() {
    try {
      file = File.createTempFile("OSS-Fuzz-", "-OSS-Fuzz");
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  public static void fuzzerTearDown() {
    file.delete();
  }

  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      // Randomize file content
      FileWriter writer = new FileWriter(file);
      writer.write(data.consumeString(data.remainingBytes()));
      writer.close();

      // Create objects of IOFileFilter
      Integer filterCount = data.consumeInt(1, 10);
      IOFileFilter[] filters = new IOFileFilter[filterCount];
      for (Integer i = 0; i < filterCount; i++) {
        Boolean negate = data.consumeBoolean();
        IOFileFilter filter = null;
        switch (data.consumeInt(1, 19)) {
          case 1:
            filter = FileFilterUtils.ageFileFilter(data.consumeLong(), data.consumeBoolean());
            break;
          case 2:
            filter = FileFilterUtils.directoryFileFilter();
            break;
          case 3:
            filter = FileFilterUtils.falseFileFilter();
            break;
          case 4:
            filter = FileFilterUtils.fileFileFilter();
            break;
          case 5:
            filter =
                FileFilterUtils.magicNumberFileFilter(data.consumeBytes(data.remainingBytes()));
            break;
          case 6:
            filter = FileFilterUtils.nameFileFilter(data.consumeString(data.remainingBytes()));
            break;
          case 7:
            filter = FileFilterUtils.prefixFileFilter(data.consumeString(data.remainingBytes()));
            break;
          case 8:
            filter = FileFilterUtils.sizeFileFilter(data.consumeLong(), data.consumeBoolean());
            break;
          case 9:
            filter = FileFilterUtils.sizeRangeFileFilter(data.consumeLong(), data.consumeLong());
            break;
          case 10:
            filter = FileFilterUtils.suffixFileFilter(data.consumeString(data.remainingBytes()));
            break;
          case 11:
            filter = CanExecuteFileFilter.CAN_EXECUTE;
            break;
          case 12:
            filter = CanReadFileFilter.CAN_READ;
            break;
          case 13:
            filter = CanReadFileFilter.READ_ONLY;
            break;
          case 14:
            filter = CanWriteFileFilter.CAN_WRITE;
            break;
          case 15:
            filter = EmptyFileFilter.EMPTY;
            break;
          case 16:
            filter = new FileEqualsFileFilter(file);
            break;
          case 17:
            filter = HiddenFileFilter.HIDDEN;
            break;
          case 18:
            filter = TrueFileFilter.INSTANCE;
            break;
          case 19:
            filter =
                WildcardFileFilter.builder()
                    .setWildcards(data.consumeString(data.remainingBytes()))
                    .get();
            break;
        }
        if (filter != null) {
          if (negate) {
            filters[i] = FileFilterUtils.notFileFilter(filter);
          } else {
            filters[i] = filter;
          }
        }
      }

      // Fuzz the accept methods of the filter list wrapped by AndFileFilter or OrFileFilter
      if ((filterCount % 2) == 0) {
        FileFilterUtils.filter(FileFilterUtils.and(filters), file);
      } else {
        FileFilterUtils.filter(FileFilterUtils.or(filters), file);
      }
    } catch (IOException | IllegalArgumentException e) {
      // Known exception
    }
  }
}
