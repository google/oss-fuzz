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
import com.google.common.reflect.ClassPath;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/** This is the base class for fuzzers requiring random class type objects */
public abstract class ClassFuzzerBase {
  private static final Integer MAX_CLASS = 1024;
  public static Set<Class> classSet;

  public static void fuzzerInitialize() throws IOException {
    classSet = getAllClasses();
  }

  public static void fuzzerTearDown() {
    classSet.clear();
    classSet = null;
  }

  public static Set<Class> getAllClasses() throws IOException {
    ClassLoader loader = ClassLoader.getSystemClassLoader();
    Set<Class> set = new HashSet<Class>();

    List<ClassPath.ClassInfo> classInfoList = ClassPath.from(loader).getAllClasses().stream().collect(Collectors.toList());
    Collections.shuffle(classInfoList);

    for (ClassPath.ClassInfo c : classInfoList) {
      if (set.size() >= MAX_CLASS) {
        break;
      }

      try {
        set.add(c.load());
      } catch (LinkageError e) {
        // Ignore
      }
    }

    return set;
  }
}
