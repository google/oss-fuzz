#!/bin/bash -eu
# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

cat > patch.diff <<- EOM
--- a/pom.xml	2022-05-05 09:49:53.028735612 +0200
+++ b/pom.xml	2022-05-05 09:49:30.445695122 +0200
@@ -120,7 +120,7 @@
      | The last stable release version id, used for generating API diffs between released versions
     -->
     <guice.lastStableRelease>5.1.0</guice.lastStableRelease>
-    <guice.skipTests>false</guice.skipTests>
+    <guice.skipTests>true</guice.skipTests>
     <gpg.skip>true</gpg.skip>
   </properties>

EOM

git apply patch.diff

cd core
cat > patch2.diff <<- EOM
--- a/pom.xml	2022-05-05 13:32:09.413975213 +0200
+++ b/pom.xml	2022-05-05 13:33:53.389402985 +0200
@@ -68,6 +68,24 @@

   <build>
     <plugins>
+      <plugin>
+        <groupId>org.apache.maven.plugins</groupId>
+        <artifactId>maven-assembly-plugin</artifactId>
+        <executions>
+          <execution>
+            <phase>package</phase>
+            <goals>
+              <goal>single</goal>
+            </goals>
+            <configuration>
+              <descriptorRefs>
+                <descriptorRef>jar-with-dependencies</descriptorRef>
+              </descriptorRefs>
+            </configuration>
+          </execution>
+        </executions>
+      </plugin>
+
       <!--
        | Add standard LICENSE and NOTICE files
       -->

EOM

git apply patch2.diff
cd ..

MAVEN_ARGS="-Djavac.src.version=15 -Djavac.target.version=15 -DskipTests"
$MVN package $MAVEN_ARGS
CURRENT_VERSION=$($MVN org.apache.maven.plugins:maven-help-plugin:3.2.0:evaluate \
 -Dexpression=project.version -q -DforceStdout)
cp "core/target/guice-$CURRENT_VERSION-jar-with-dependencies.jar" "$OUT/guice.jar"

ALL_JARS="guice.jar"

# The classpath at build-time includes the project jars in $OUT as well as the
# Jazzer API.
BUILD_CLASSPATH=$(echo $ALL_JARS | xargs printf -- "$OUT/%s:"):$JAZZER_API_PATH

# All .jar and .class files lie in the same directory as the fuzzer at runtime.
RUNTIME_CLASSPATH=$(echo $ALL_JARS | xargs printf -- "\$this_dir/%s:"):\$this_dir

for fuzzer in $(find $SRC -name '*Fuzzer.java'); do
  fuzzer_basename=$(basename -s .java $fuzzer)
  javac -cp $BUILD_CLASSPATH $fuzzer
  cp $SRC/$fuzzer_basename*.class $OUT/

  # Create an execution wrapper that executes Jazzer with the correct arguments.
  echo "#!/bin/bash
# LLVMFuzzerTestOneInput for fuzzer detection.
this_dir=\$(dirname \"\$0\")
if [[ \"\$@\" =~ (^| )-runs=[0-9]+($| ) ]]; then
  mem_settings='-Xmx1900m:-Xss900k'
else
  mem_settings='-Xmx2048m:-Xss1024k'
fi
LD_LIBRARY_PATH=\"$JVM_LD_LIBRARY_PATH\":\$this_dir \
\$this_dir/jazzer_driver --agent_path=\$this_dir/jazzer_agent_deploy.jar \
--cp=$RUNTIME_CLASSPATH \
--target_class=$fuzzer_basename \
--jvm_args=\"\$mem_settings\" \
--disabled_hooks=\"com.code_intelligence.jazzer.sanitizers.ReflectiveCall\" \
\$@" > $OUT/$fuzzer_basename
  chmod u+x $OUT/$fuzzer_basename
done
