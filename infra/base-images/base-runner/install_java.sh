#! /bin/bash


ARCHITECTURE=
case $(uname -m) in
    x86_64)
	ARCHITECTURE=x64
        ;;
    aarch64)
	
        ;;
    *)
        ARCHITECTURE=aarch64
        exit 1
        ;;
esac

wget https://download.java.net/java/GA/jdk15.0.2/0d1cfde4252546c6931946de8db48ee2/7/GPL/openjdk-15.0.2_linux-"$ARCHITECTURE"_bin.tar.gz -O /tmp/openjdk-15.0.2_linux-"$ARCHITECTURE"_bin.tar.gz
cd /tmp
mkdir -p $JAVA_HOME
tar -xzv --strip-components=1 -f openjdk-15.0.2_linux-"$ARCHITECTURE"_bin.tar.gz --directory $JAVA_HOME
rm -f openjdk-15.0.2_linux-"$ARCHITECTURE"_bin.tar.gz
rm -rf $JAVA_HOME/jmods $JAVA_HOME/lib/src.zip
