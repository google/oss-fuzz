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
import java.lang.annotation.Annotation;
import java.lang.reflect.AnnotatedElement;
import java.util.HashSet;
import java.util.Set;
import org.apache.commons.lang3.AnnotationUtils;
import org.apache.commons.lang3.exception.UncheckedException;

/** This fuzzer targets the methods of the AnnotationUtils class. */
public class AnnotationUtilsFuzzer extends ClassFuzzerBase {
  private static Set<Annotation> annotationSet;

  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      AnnotationUtils.isValidAnnotationMemberType(data.pickValue(classSet));

      initializeAnnotationSet();

      // Randomly pick 2 annotations object
      Annotation annotation1 = data.pickValue(annotationSet);
      Annotation annotation2 = data.pickValue(annotationSet);

      switch (data.consumeInt(1, 3)) {
        case 1:
          AnnotationUtils.toString(annotation1);
          AnnotationUtils.toString(annotation2);
          break;
        case 2:
          AnnotationUtils.equals(annotation1, annotation2);
          break;
        case 3:
          AnnotationUtils.hashCode(annotation1);
          AnnotationUtils.hashCode(annotation2);
          break;
      }
    } catch (UncheckedException e) {
      // Known exception
    }
  }

  private static void initializeAnnotationSet() {
    if ((annotationSet == null) || (annotationSet.size() == 0)) {
      annotationSet = new HashSet<Annotation>();
      for (Class cls : classSet) {
        try {
          Set<AnnotatedElement> elements = new HashSet<AnnotatedElement>();
          elements.add(cls);
          elements.add(cls.getPackage());
          elements.addAll(Set.of(cls.getConstructors()));
          elements.addAll(Set.of(cls.getMethods()));
          elements.addAll(Set.of(cls.getFields()));
          for (AnnotatedElement element : elements) {
            annotationSet.addAll(Set.of(element.getAnnotations()));
          }
        } catch (LinkageError e) {
          // Ignore failing classes
        }
      }
    }
  }
}
