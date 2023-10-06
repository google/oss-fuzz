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

find $SRC/spring* -name *.dict -o -name *zip -exec cp {} $OUT/ \;

export JAVA_HOME="$OUT/open-jdk-17"
mkdir -p $JAVA_HOME
rsync -aL --exclude=*.zip "/usr/lib/jvm/java-17-openjdk-amd64/" "$JAVA_HOME"

export CURRENT_VERSION=$(./gradlew properties --console=plain | sed -nr "s/^version:\ (.*)/\1/p")

function install_shadowJar {
    if grep -q shadow $1/$1.gradle; then
	    ./gradlew shadowJar --build-file $1/$1.gradle -x javadoc -x test
    	install -v "$1/build/libs/$1-$CURRENT_VERSION-all.jar" "$OUT/$1.jar";
    else
        ./gradlew build -x javadoc -x test
        install -v "$1/build/libs/$1-$CURRENT_VERSION.jar" "$OUT/$1.jar";
    fi
}

install_shadowJar spring-context
install_shadowJar spring-core
install_shadowJar spring-jdbc
install_shadowJar spring-orm
install_shadowJar spring-web
install_shadowJar spring-webmvc
install_shadowJar spring-test
install_shadowJar spring-tx
install_shadowJar spring-messaging
install_shadowJar spring-jms
install_shadowJar spring-webflux
install_shadowJar spring-websocket
install_shadowJar spring-oxm

ALL_JARS=$(find $OUT -name "spring*.jar" -printf "%f ")

# The classpath at build-time includes the project jars in $OUT as well as the
# Jazzer API.
export BUILD_CLASSPATH=$(echo $ALL_JARS | xargs printf -- "$OUT/%s:"):$JAZZER_API_PATH:$SRC

# All .jar and .class files lie in the same directory as the fuzzer at runtime.
export RUNTIME_CLASSPATH=$(echo $ALL_JARS | xargs printf -- "\$this_dir/%s:"):\$this_dir

function create_fuzz_targets() {
    mkdir -p $SRC/$1
    mkdir -p $OUT/$1
    javac -cp $BUILD_CLASSPATH --release 17 $(find $SRC/$1/ -name "*.java" -print)

    # Overwrite class path for some projects
    if [ $# -eq 2 ]; then
        RUNTIME_CLASSPATH=$2
    fi

    for fuzzer in $SRC/$1/*Fuzzer.java; do
        fuzzer_basename=$(basename -s .java $fuzzer)

        # Create an execution wrapper that executes Jazzer with the correct arguments.
        echo "#!/bin/bash
        # LLVMFuzzerTestOneInput for fuzzer detection.
        this_dir=\$(dirname \"\$0\")
        JAVA_OPTS=\"-Dorg.apache.commons.logging.Log=org.apache.commons.logging.impl.NoOpLog\" \
        JAVA_HOME=\"\$this_dir/open-jdk-17/\" \
        LD_LIBRARY_PATH=\"\$this_dir/open-jdk-17/lib/server\":\$this_dir \
        if [[ \"\$@\" =~ (^| )-runs=[0-9]+($| ) ]]; then
            mem_settings='-Xmx1900m:-Xss900k'
        else
            mem_settings='-Xmx2048m:-Xss1024k'
        fi
        \$this_dir/jazzer_driver --agent_path=\$this_dir/jazzer_agent_deploy.jar \
        --cp=$RUNTIME_CLASSPATH \
        --target_class=$fuzzer_basename \
        --instrumentation_includes=org.springframework.** \
        --jvm_args=\"\$mem_settings:-Dorg.apache.commons.logging.Log=org.apache.commons.logging.impl.NoOpLog\" \
        \$@" > $OUT/$fuzzer_basename
        chmod u+x $OUT/$fuzzer_basename
    done

    cp $SRC/$1/*.class $OUT/
}

create_fuzz_targets spring-aop
create_fuzz_targets spring-beans
create_fuzz_targets spring-context
create_fuzz_targets spring-expression
create_fuzz_targets spring-tx
create_fuzz_targets spring-web
create_fuzz_targets spring-jdbc
create_fuzz_targets spring-messaging
create_fuzz_targets spring-jms
create_fuzz_targets spring-webflux
create_fuzz_targets spring-oxm
create_fuzz_targets spring-websocket "\$this_dir/spring-websocket.jar:\$this_dir"; # Overwrite class path to avoid logging to stdout

cp $SRC/spring-jdbc/*.xml $OUT/spring-jdbc/
