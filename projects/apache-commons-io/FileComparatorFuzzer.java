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
import java.util.Comparator;
import java.util.LinkedList;
import java.util.List;
import org.apache.commons.io.comparator.CompositeFileComparator;
import org.apache.commons.io.comparator.DefaultFileComparator;
import org.apache.commons.io.comparator.DirectoryFileComparator;
import org.apache.commons.io.comparator.ExtensionFileComparator;
import org.apache.commons.io.comparator.LastModifiedFileComparator;
import org.apache.commons.io.comparator.NameFileComparator;
import org.apache.commons.io.comparator.PathFileComparator;
import org.apache.commons.io.comparator.SizeFileComparator;

/** This fuzzer targets the different Comparator classes for files in the comparator package. */
public class FileComparatorFuzzer {
  private static File file1;
  private static File file2;

  public static void fuzzerInitialize() {
    try {
      file1 = File.createTempFile("OSS-Fuzz-", "-OSS-Fuzz");
      file2 = File.createTempFile("OSS-Fuzz-", "-OSS-Fuzz");
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  public static void fuzzerTearDown() {
    file1.delete();
    file2.delete();
  }

  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      // Randomize file content
      FileWriter writer = new FileWriter(file1);
      writer.write(data.consumeString(data.remainingBytes()));
      writer.close();
      writer = new FileWriter(file2);
      writer.write(data.consumeString(data.remainingBytes()));
      writer.close();

      // Create list of files
      List<File> files = new LinkedList<File>();
      files.add(file1);
      files.add(file2);

      // Create objects of comparator
      Integer comparatorCount = data.consumeInt(1, 10);
      List<Comparator<File>> delegates = new LinkedList<Comparator<File>>();
      for (Integer i = 0; i < comparatorCount; i++) {
        switch (data.consumeInt(1, 28)) {
          case 1:
            delegates.add(DefaultFileComparator.DEFAULT_COMPARATOR);
            break;
          case 2:
            delegates.add(DefaultFileComparator.DEFAULT_REVERSE);
            break;
          case 3:
            delegates.add(DirectoryFileComparator.DIRECTORY_COMPARATOR);
            break;
          case 4:
            delegates.add(DirectoryFileComparator.DIRECTORY_REVERSE);
            break;
          case 5:
            delegates.add(ExtensionFileComparator.EXTENSION_COMPARATOR);
            break;
          case 6:
            delegates.add(ExtensionFileComparator.EXTENSION_REVERSE);
            break;
          case 7:
            delegates.add(ExtensionFileComparator.EXTENSION_INSENSITIVE_COMPARATOR);
            break;
          case 8:
            delegates.add(ExtensionFileComparator.EXTENSION_INSENSITIVE_REVERSE);
            break;
          case 9:
            delegates.add(ExtensionFileComparator.EXTENSION_SYSTEM_COMPARATOR);
            break;
          case 10:
            delegates.add(ExtensionFileComparator.EXTENSION_SYSTEM_REVERSE);
            break;
          case 11:
            delegates.add(LastModifiedFileComparator.LASTMODIFIED_COMPARATOR);
            break;
          case 12:
            delegates.add(LastModifiedFileComparator.LASTMODIFIED_REVERSE);
            break;
          case 13:
            delegates.add(NameFileComparator.NAME_COMPARATOR);
            break;
          case 14:
            delegates.add(NameFileComparator.NAME_REVERSE);
            break;
          case 15:
            delegates.add(NameFileComparator.NAME_INSENSITIVE_COMPARATOR);
            break;
          case 16:
            delegates.add(NameFileComparator.NAME_INSENSITIVE_REVERSE);
            break;
          case 17:
            delegates.add(NameFileComparator.NAME_SYSTEM_COMPARATOR);
            break;
          case 18:
            delegates.add(NameFileComparator.NAME_SYSTEM_REVERSE);
            break;
          case 19:
            delegates.add(PathFileComparator.PATH_COMPARATOR);
            break;
          case 20:
            delegates.add(PathFileComparator.PATH_REVERSE);
            break;
          case 21:
            delegates.add(PathFileComparator.PATH_INSENSITIVE_COMPARATOR);
            break;
          case 22:
            delegates.add(PathFileComparator.PATH_INSENSITIVE_REVERSE);
            break;
          case 23:
            delegates.add(PathFileComparator.PATH_SYSTEM_COMPARATOR);
            break;
          case 24:
            delegates.add(PathFileComparator.PATH_SYSTEM_REVERSE);
            break;
          case 25:
            delegates.add(SizeFileComparator.SIZE_COMPARATOR);
            break;
          case 26:
            delegates.add(SizeFileComparator.SIZE_REVERSE);
            break;
          case 27:
            delegates.add(SizeFileComparator.SIZE_SUMDIR_COMPARATOR);
            break;
          case 28:
            delegates.add(SizeFileComparator.SIZE_SUMDIR_REVERSE);
            break;
        }
      }

      // Fuzz the comparator by calling sort method of the file list
      files.sort(new CompositeFileComparator(delegates));
    } catch (IOException e) {
      // Known exception
    }
  }
}
