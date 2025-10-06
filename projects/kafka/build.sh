#!/bin/bash
set -e

./gradlew jar -x test

javac -cp "$(find . -name '*.jar' | tr '\n' ':')$SRC" \
      $SRC/*.java

cp *.class $OUT/
cp build/libs/*.jar $OUT/

echo "kafka OSS-Fuzz build completed"
