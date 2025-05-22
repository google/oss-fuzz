#!/bin/bash -eu
# Copyright 2023 Google LLC
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
##########################################################################
$MVN clean package -Dmaven.javadoc.skip=true -DskipTests=true -Dpmd.skip=true \
    -Dencoding=UTF-8 -Dmaven.antrun.skip=true -Dcheckstyle.skip=true \
    -DperformRelease=True org.apache.maven.plugins:maven-shade-plugin:3.2.4:shade
CURRENT_VERSION=$($MVN org.apache.maven.plugins:maven-help-plugin:3.2.0:evaluate \
 -Dexpression=project.version -q -DforceStdout)

JARFILE_LIST=
for JARFILE in $(find ./  -name *.jar)
do
  if [[ "$JARFILE" == *"target/"* ]] && [[ "$JARFILE" != *original*.jar ]]
  then
    if [[ "$JARFILE" != *sources.jar ]] && [[ "$JARFILE" != *javadoc.jar ]] && [[ "$JARFILE" != *tests.jar ]]
    then
      cp $JARFILE $OUT/
      JARFILE_LIST="$JARFILE_LIST$(basename $JARFILE) "
    fi
  fi
done

curr_dir=$(pwd)
rm -rf $OUT/jar_temp
mkdir $OUT/jar_temp
cd $OUT/jar_temp
for JARFILE in $JARFILE_LIST
do
  jar -xf $OUT/$JARFILE
done
cd $curr_dir

cp -r $JAVA_HOME $OUT/

BUILD_CLASSPATH=$JAZZER_API_PATH:$OUT/jar_temp
RUNTIME_CLASSPATH=\$this_dir/jar_temp:\$this_dir

for fuzzer in $(find $SRC -maxdepth 1 -name '*Fuzzer.java')
do
  fuzzer_basename=$(basename -s .java $fuzzer)
  $JAVA_HOME/bin/javac -cp $BUILD_CLASSPATH $fuzzer
  cp $SRC/$fuzzer_basename*.class $OUT/

  # Create an execution wrapper that executes Jazzer with the correct arguments.
  echo "#!/bin/bash
  # LLVMFuzzerTestOneInput for fuzzer detection.
  this_dir=\$(dirname "\$0")
  if [[ "\$@" =~ (^| )-runs=[0-9]+($| ) ]]
  then
    mem_settings='-Xmx1900m:-Xss900k'
  else
    mem_settings='-Xmx2048m:-Xss1024k'
  fi

  export JAVA_HOME=\$this_dir/$(basename $JAVA_HOME)
  export LD_LIBRARY_PATH="\$JAVA_HOME/lib/server":\$this_dir
  export PATH=\$JAVA_HOME/bin:\$PATH

  \$this_dir/jazzer_driver                          \
    --agent_path=\$this_dir/jazzer_agent_deploy.jar \
    --cp=$RUNTIME_CLASSPATH                         \
    --target_class=$fuzzer_basename                 \
    --jvm_args="\$mem_settings"                     \
    \$@" > $OUT/$fuzzer_basename

    chmod u+x $OUT/$fuzzer_basename
done
