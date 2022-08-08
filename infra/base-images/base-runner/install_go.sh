#! /bin/bash


case $(uname -m) in
    x86_64)
	# Download and install the latest stable Go.
	wget https://storage.googleapis.com/golang/getgo/installer_linux
	chmod +x $SRC/installer_linux
	SHELL="bash" $SRC/installer_linux -version 1.18beta2
	rm $SRC/installer_linux
	# Set up Golang coverage modules.
	COPY gocoverage $GOPATH/gocoverage
	RUN cd $GOPATH/gocoverage && go install ./...
        ;;
    aarch64)
	echo "Not installing go; aarch64"
        ;;
    *)
        echo "Error: unsupported target $(uname -m)"
        exit 1
        ;;
esac
